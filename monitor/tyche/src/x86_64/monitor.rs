//! Architecture specific monitor state, independant of the CapaEngine.

use core::sync::atomic::{AtomicBool, Ordering};

use attestation::signature::EnclaveReport;
use capa_engine::config::{NB_CORES, NB_DOMAINS};
use capa_engine::utils::BitmapIterator;
use capa_engine::{
    permission, AccessRights, Bitmaps, Buffer, CapaEngine, CapaError, CapaInfo, Domain, GenArena,
    Handle, LocalCapa, MemOps, NextCapaToken, MEMOPS_ALL,
};
use mmu::eptmapper::EPT_ROOT_FLAGS;
use mmu::{EptMapper, FrameAllocator, IoPtFlag, IoPtMapper};
use spin::barrier::Barrier;
use spin::{Mutex, MutexGuard};
use stage_two_abi::Manifest;
use utils::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};
use vmx::bitmaps::{EptEntryFlags, ExceptionBitmap};
use vmx::errors::Trapnr;
use vmx::msr::{IA32_LSTAR, IA32_STAR};
use vmx::{ActiveVmcs, ControlRegister, Register, VmExitInterrupt, REGFILE_SIZE};
use vtd::Iommu;

use super::cpuid;
use super::guest::VmxState;
use super::init::NB_BOOTED_CORES;
use crate::allocator::{allocator, PAGE_SIZE};
use crate::attestation_domain::{attest_domain, calculate_attestation_hash};
use crate::rcframe::{drop_rc, RCFrame, RCFramePool, EMPTY_RCFRAME};
use crate::x86_64::apic;
// ————————————————————————— Statics & Backend Data ————————————————————————— //

static CAPA_ENGINE: Mutex<CapaEngine> = Mutex::new(CapaEngine::new());
static IO_DOMAIN: Mutex<Option<LocalCapa>> = Mutex::new(None);
static INITIAL_DOMAIN: Mutex<Option<Handle<Domain>>> = Mutex::new(None);
static DOMAINS: [Mutex<DomainData>; NB_DOMAINS] = [EMPTY_DOMAIN; NB_DOMAINS];
static CORE_UPDATES: [Mutex<Buffer<CoreUpdate>>; NB_CORES] = [EMPTY_UPDATE_BUFFER; NB_CORES];
static CONTEXTS: [[Mutex<ContextData>; NB_CORES]; NB_DOMAINS] = [EMPTY_CONTEXT_ARRAY; NB_DOMAINS];
static RC_VMCS: Mutex<RCFramePool> =
    Mutex::new(GenArena::new([EMPTY_RCFRAME; { NB_DOMAINS * NB_CORES }]));
const BARRIER: Option<Barrier> = None;
const FALSE: AtomicBool = AtomicBool::new(false);
static mut TLB_FLUSH_BARRIERS: [Option<Barrier>; NB_DOMAINS] = [BARRIER; NB_DOMAINS];
static TLB_FLUSH: [AtomicBool; NB_DOMAINS] = [FALSE; NB_DOMAINS];

pub struct DomainData {
    ept: Option<HostPhysAddr>,
    ept_old: Option<HostPhysAddr>,
    iopt: Option<HostPhysAddr>,
}

pub struct ContextData {
    pub cr3: usize,
    pub rip: usize,
    pub rsp: usize,
    // General-purpose registers.
    pub regs: [u64; REGFILE_SIZE],
    // The MSR(s?) we need to save and restore.
    pub star: u64,
    pub lstar: u64,
    /// Vcpu for this core.
    pub vmcs: Handle<RCFrame>,
}

impl ContextData {
    pub fn save_partial(&mut self, vcpu: &ActiveVmcs<'static>) {
        self.cr3 = vcpu.get_cr(ControlRegister::Cr3);
        self.rip = vcpu.get(Register::Rip) as usize;
        self.rsp = vcpu.get(Register::Rsp) as usize;
    }

    pub fn save(&mut self, vcpu: &mut ActiveVmcs<'static>) {
        self.save_partial(vcpu);
        vcpu.dump_regs(&mut self.regs);
        self.lstar = unsafe { IA32_LSTAR.read() };
        self.star = unsafe { IA32_STAR.read() };
        vcpu.flush();
    }

    pub fn restore_partial(&self, vcpu: &mut ActiveVmcs<'static>) {
        log::trace!(
            "Switching info cr3 : {:#x}, rip : {:#x}, rsp : {:#x}",
            self.cr3,
            self.rip as u64,
            self.rsp as u64
        );
        vcpu.set_cr(ControlRegister::Cr3, self.cr3);
        vcpu.set(Register::Rip, self.rip as u64);
        vcpu.set(Register::Rsp, self.rsp as u64);
    }

    pub fn restore(&self, vcpu: &mut ActiveVmcs<'static>) {
        let locked = RC_VMCS.lock();
        let rc_frame = locked.get(self.vmcs).unwrap();
        vcpu.load_regs(&self.regs);
        unsafe { vmx::msr::Msr::new(IA32_LSTAR.address()).write(self.lstar) };
        unsafe { vmx::msr::Msr::new(IA32_STAR.address()).write(self.star) };
        vcpu.switch_frame(rc_frame.frame).unwrap();
        // Restore partial must be called AFTER we set a valid frame.
        self.restore_partial(vcpu);
    }
}

#[repr(u64)]
pub enum InitVMCS {
    Shared = 1,
    Copy = 2,
    Fresh = 3,
}

impl InitVMCS {
    pub fn from_u64(v: u64) -> Result<Self, CapaError> {
        match v {
            1 => Ok(Self::Shared),
            2 => Ok(Self::Copy),
            3 => Ok(Self::Fresh),
            _ => Err(CapaError::InvalidOperation),
        }
    }
}

const EMPTY_DOMAIN: Mutex<DomainData> = Mutex::new(DomainData {
    ept: None,
    ept_old: None,
    iopt: None,
});
const EMPTY_UPDATE_BUFFER: Mutex<Buffer<CoreUpdate>> = Mutex::new(Buffer::new());
const EMPTY_CONTEXT: Mutex<ContextData> = Mutex::new(ContextData {
    cr3: usize::max_value(),
    rip: usize::max_value(),
    rsp: usize::max_value(),
    regs: [0; REGFILE_SIZE],
    lstar: u64::max_value(),
    star: u64::max_value(),
    vmcs: Handle::<RCFrame>::new_invalid(),
});
const EMPTY_CONTEXT_ARRAY: [Mutex<ContextData>; NB_CORES] = [EMPTY_CONTEXT; NB_CORES];
static IOMMU: Mutex<Iommu> =
    Mutex::new(unsafe { Iommu::new(HostVirtAddr::new(usize::max_value())) });

// ————————————————————————————— Initialization ————————————————————————————— //

pub fn init(manifest: &'static Manifest) {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.create_manager_domain(permission::ALL).unwrap();
    apply_updates(&mut engine);
    engine
        .create_root_region(
            domain,
            AccessRights {
                start: 0,
                end: manifest.iommu as usize,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    engine
        .create_root_region(
            domain,
            AccessRights {
                start: (manifest.iommu + PAGE_SIZE) as usize,
                end: manifest.poffset as usize,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    apply_updates(&mut engine);

    // Save the initial domain
    let mut initial_domain = INITIAL_DOMAIN.lock();
    *initial_domain = Some(domain);

    // Create and save the I/O domain
    let io_domain = engine.create_io_domain(domain).unwrap();
    let mut initial_io_domain = IO_DOMAIN.lock();
    *initial_io_domain = Some(io_domain);

    if manifest.iommu != 0 {
        let mut iommu = IOMMU.lock();
        iommu.set_addr(manifest.iommu as usize);
    }
}

pub fn init_vcpu(vcpu: &mut ActiveVmcs<'static>) -> Handle<Domain> {
    let cpuid = cpuid();
    let mut engine = CAPA_ENGINE.lock();
    let initial_domain = INITIAL_DOMAIN
        .lock()
        .expect("CapaEngine is not initialized yet");
    engine
        .start_domain_on_core(initial_domain, cpuid)
        .expect("Failed to allocate initial domain");
    let domain = get_domain(initial_domain);
    let mut ctxt = get_context(initial_domain, cpuid);
    let rcframe = RC_VMCS
        .lock()
        .allocate(RCFrame::new(*vcpu.frame()))
        .expect("Unable to allocate rcframe");
    ctxt.vmcs = rcframe;
    vcpu.set_ept_ptr(HostPhysAddr::new(
        domain.ept.unwrap().as_usize() | EPT_ROOT_FLAGS,
    ))
    .expect("Failed to set initial EPT PTR");
    initial_domain
}

// ———————————————————————————————— Helpers ————————————————————————————————— //

fn get_domain(domain: Handle<Domain>) -> MutexGuard<'static, DomainData> {
    DOMAINS[domain.idx()].lock()
}

fn get_context(domain: Handle<Domain>, core: usize) -> MutexGuard<'static, ContextData> {
    CONTEXTS[domain.idx()][core].lock()
}

// ————————————————————————————— Monitor Calls —————————————————————————————— //

pub fn do_create_domain(current: Handle<Domain>) -> Result<LocalCapa, CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let management_capa = engine.create_domain(current)?;
    apply_updates(&mut engine);
    Ok(management_capa)
}

pub fn do_set_config(
    current: Handle<Domain>,
    domain: LocalCapa,
    bitmap: Bitmaps,
    value: u64,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    engine.set_child_config(current, domain, bitmap, value)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_init_child_contexts(
    current: Handle<Domain>,
    domain: LocalCapa,
    vcpu: &mut ActiveVmcs<'static>,
) {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine
        .get_domain_capa(current, domain)
        .expect("Unable to access child");
    let value = engine.get_domain_config(domain, Bitmaps::SWITCH);
    let value = InitVMCS::from_u64(value).unwrap();
    let allocator = allocator();
    // Init on all the cores.
    let cpus = 0..(NB_BOOTED_CORES.load(core::sync::atomic::Ordering::SeqCst) + 1);
    let mut rcvmcs = RC_VMCS.lock();
    let cores = engine.get_domain_config(domain, Bitmaps::CORE);
    match value {
        InitVMCS::Shared => {
            // Easy case, increase ref on all cores shared by the two domains.
            for c in cpus {
                if (1 << c) & cores == 0 {
                    continue;
                }
                let orig = get_context(current, c);
                let dest = &mut get_context(domain, c);
                rcvmcs
                    .get_mut(orig.vmcs)
                    .expect("No vmcs on original")
                    .acquire();
                if !dest.vmcs.is_invalid() {
                    drop_rc(&mut rcvmcs, dest.vmcs);
                }
                dest.vmcs = orig.vmcs;
            }
        }
        InitVMCS::Copy => {
            // Flush the current vcpu.
            for c in cpus {
                if (1 << c) & cores == 0 {
                    continue;
                }
                let dest = &mut get_context(domain, c);
                let frame = allocator
                    .allocate_frame()
                    .expect("Unable to allocate frame");
                let rc = RCFrame::new(frame);
                dest.vmcs = rcvmcs.allocate(rc).expect("Unable to allocate rc frame");
                vcpu.copy_into(frame);
            }
        }
        InitVMCS::Fresh => {
            for c in cpus {
                if (1 << c) & cores == 0 {
                    continue;
                }
                let dest = &mut get_context(domain, c);
                let frame = allocator
                    .allocate_frame()
                    .expect("Unable to allocate frame");
                let rc = RCFrame::new(frame);
                //TODO do an init;
                dest.vmcs = rcvmcs.allocate(rc).expect("Unable to allocate rc frame");
            }
        }
    }
}

pub fn do_set_entry(
    current: Handle<Domain>,
    domain: LocalCapa,
    core: usize,
    cr3: usize,
    rip: usize,
    rsp: usize,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.get_domain_capa(current, domain)?;
    let cores = engine.get_domain_config(domain, Bitmaps::CORE);
    if (1 << core) & cores == 0 {
        return Err(CapaError::InvalidCore);
    }
    let context = &mut get_context(domain, core);
    if context.vmcs.is_invalid() {
        log::error!("Set the switch type first!");
        return Err(CapaError::InvalidOperation);
    }
    context.cr3 = cr3;
    context.rip = rip;
    context.rsp = rsp;
    Ok(())
}

/// TODO(aghosn) do we need to seal on all cores?
pub fn do_seal(current: Handle<Domain>, domain: LocalCapa) -> Result<LocalCapa, CapaError> {
    let core = cpuid();
    let mut engine = CAPA_ENGINE.lock();

    let capa = engine.seal(current, core, domain)?;

    if let Ok(domain_capa) = engine.get_domain_capa(current, domain) {
        calculate_attestation_hash(&mut engine, domain_capa);
    }

    apply_updates(&mut engine);
    Ok(capa)
}

pub fn do_segment_region(
    current: Handle<Domain>,
    capa: LocalCapa,
    start_1: usize,
    end_1: usize,
    prot_1: usize,
    start_2: usize,
    end_2: usize,
    prot_2: usize,
) -> Result<(LocalCapa, LocalCapa), CapaError> {
    let prot_1 = MemOps::from_usize(prot_1)?;
    let prot_2 = MemOps::from_usize(prot_2)?;
    let mut engine = CAPA_ENGINE.lock();
    let access_left = AccessRights {
        start: start_1,
        end: end_1,
        ops: prot_1,
    };
    let access_right = AccessRights {
        start: start_2,
        end: end_2,
        ops: prot_2,
    };
    let (left, right) = engine.segment_region(current, capa, access_left, access_right)?;
    apply_updates(&mut engine);
    Ok((left, right))
}

pub fn do_send(current: Handle<Domain>, capa: LocalCapa, to: LocalCapa) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    engine.send(current, capa, to)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_enumerate(
    current: Handle<Domain>,
    token: NextCapaToken,
) -> Option<(CapaInfo, NextCapaToken)> {
    let mut engine = CAPA_ENGINE.lock();
    engine.enumerate(current, token)
}

pub fn do_revoke(current: Handle<Domain>, capa: LocalCapa) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    engine.revoke(current, capa)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_duplicate(current: Handle<Domain>, capa: LocalCapa) -> Result<LocalCapa, CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let new_capa = engine.duplicate(current, capa)?;
    apply_updates(&mut engine);
    Ok(new_capa)
}

pub fn do_switch(current: Handle<Domain>, capa: LocalCapa, cpuid: usize) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    engine.switch(current, cpuid, capa)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_debug() {
    let mut engine = CAPA_ENGINE.lock();
    let mut next = NextCapaToken::new();
    while let Some((domain, next_next)) = engine.enumerate_domains(next) {
        next = next_next;

        log::trace!("Domain");
        let mut next_capa = NextCapaToken::new();
        while let Some((info, next_next_capa)) = engine.enumerate(domain, next_capa) {
            next_capa = next_next_capa;
            log::trace!(" - {}", info);
        }
        log::trace!(
            "{}",
            engine.get_domain_regions(domain).expect("Invalid domain")
        );
    }
}

pub fn do_domain_attestation(
    current: Handle<Domain>,
    nonce: usize,
    mode: usize,
) -> Option<EnclaveReport> {
    let mut engine = CAPA_ENGINE.lock();
    attest_domain(&mut engine, current, nonce, mode)
}

// —————————————————————— Interrupt Handling functions —————————————————————— //

pub fn handle_trap(
    current: Handle<Domain>,
    core: usize,
    trap: VmExitInterrupt,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    engine.handle_trap(current, core, trap.get_trap_number(), trap.as_info())?;
    apply_updates(&mut engine);
    Ok(())
}

// ———————————————————————————————— Updates ————————————————————————————————— //

/// Per-core updates
#[derive(Debug, Clone, Copy)]
enum CoreUpdate {
    TlbShootdown,
    Switch {
        domain: Handle<Domain>,
        return_capa: LocalCapa,
    },
    Trap {
        manager: Handle<Domain>,
        trap: u64,
        info: u64,
    },
    UpdateTrap {
        bitmap: u64,
    },
}

fn post_ept_update(core_id: usize, cores: u64, domain: &Handle<Domain>) {
    let core_cnt = cores.count_ones();
    log::trace!(
        "core{}: post_ept_update with core_cnt={}",
        cpuid(),
        core_cnt
    );

    unsafe {
        TLB_FLUSH_BARRIERS[domain.idx()] = Some(spin::barrier::Barrier::new(core_cnt as usize));
    }
    notify_cores(core_id, cores);

    unsafe {
        TLB_FLUSH_BARRIERS[domain.idx()].as_mut().unwrap().wait();
    }

    // If I am the initiating core, then I'm responsible for freeing the original EPT
    // root.
    log::trace!("core {} freeing the original domain EPT", core_id);
    free_original_ept_root(domain);
    // We're done with the current TLB flush update
    log::trace!("core {} allows more TLB flushes", core_id);
    TLB_FLUSH[domain.idx()].store(false, Ordering::SeqCst);
}

fn push_core_update(core: usize) {
    log::trace!("cpu {} pushes Tlbshootdown to core={}", cpuid(), core);
    let mut core_updates = CORE_UPDATES[core as usize].lock();
    core_updates.push(CoreUpdate::TlbShootdown);
}

/// General updates, containing both global updates on the domain's states, and core specific
/// updates that must be routed to the different cores.
fn apply_updates(engine: &mut MutexGuard<CapaEngine>) {
    while let Some(update) = engine.pop_update() {
        log::trace!("Update: {}", update);
        match update {
            // Updates that can be handled locally
            capa_engine::Update::PermissionUpdate {
                domain,
                init,
                core_map,
            } => {
                let core_id = cpuid();
                log::trace!(
                    "cpu {} processes PermissionUpdate with core_map={:b}",
                    core_id,
                    core_map
                );
                let ept_update = update_permission(domain, engine, init);

                if !init && ept_update {
                    log::trace!(
                        "cpu {} pushes core update with core_map={:b}",
                        cpuid(),
                        core_map
                    );
                    // Push TlbShootdown directly into the per-core queue
                    for core in BitmapIterator::new(core_map) {
                        if core_id != core {
                            push_core_update(core);
                        }
                    }

                    // After we have pushed all TlbShootdown updates to its per cpu CORE_UPDATES, we
                    // can issue the IPI now.
                    post_ept_update(core_id, core_map, &domain);
                }
            }
            capa_engine::Update::RevokeDomain { domain } => revoke_domain(domain),
            capa_engine::Update::CreateDomain { domain } => create_domain(domain),

            // Updates that needs to be routed to some specific cores
            capa_engine::Update::Switch {
                domain,
                return_capa,
                core,
            } => {
                let mut core_updates = CORE_UPDATES[core as usize].lock();
                core_updates.push(CoreUpdate::Switch {
                    domain,
                    return_capa,
                });
            }
            capa_engine::Update::Trap {
                manager,
                trap,
                info,
                core,
            } => {
                let mut core_updates = CORE_UPDATES[core as usize].lock();
                core_updates.push(CoreUpdate::Trap {
                    manager,
                    trap,
                    info,
                });
            }
            capa_engine::Update::UpdateTraps { trap, core } => {
                let mut core_updates = CORE_UPDATES[core as usize].lock();
                core_updates.push(CoreUpdate::UpdateTrap { bitmap: !trap });
            }
        }
    }
}

fn tlb_shootdown(core_id: usize, current_domain: &mut Handle<Domain>, vcpu: &mut ActiveVmcs) {
    log::info!("EPT Root update on core {}", core_id);
    // Reload the EPTs
    let domain = get_domain(*current_domain);
    log::info!(
        "core {}: domain.ept={:#x}",
        core_id,
        domain.ept.unwrap().as_usize()
    );
    vcpu.set_ept_ptr(HostPhysAddr::new(
        domain.ept.unwrap().as_usize() | EPT_ROOT_FLAGS,
    ))
    .expect("VMX error, failed to set EPT pointer");
}

fn free_original_ept_root(current_domain: &Handle<Domain>) {
    let mut domain = get_domain(*current_domain);
    let allocator = allocator();
    if let Some(ept) = domain.ept_old {
        unsafe { free_ept(ept, allocator) };
    }
    domain.ept_old = None;
}

/// Updates that must be applied to a given core.
pub fn apply_core_updates(
    vmx_state: &mut VmxState,
    current_domain: &mut Handle<Domain>,
    core_id: usize,
) {
    let core = cpuid();
    let vcpu = &mut vmx_state.vcpu;
    let mut update_queue = CORE_UPDATES[core_id].lock();
    while let Some(update) = update_queue.pop() {
        log::trace!("Core Update: {}", update);
        match update {
            CoreUpdate::TlbShootdown => {
                // Into a separate function so that we can drop the domain lock before starting to
                // wait on the TLB_FLUSH_BARRIER
                tlb_shootdown(core_id, current_domain, vcpu);
                log::trace!("core {} waits on tlb flush barrier", core_id);
                unsafe {
                    TLB_FLUSH_BARRIERS[current_domain.idx()]
                        .as_mut()
                        .unwrap()
                        .wait();
                }
                log::trace!("core {} finished waiting", core_id);
            }
            CoreUpdate::Switch {
                domain,
                return_capa,
            } => {
                log::trace!("Domain Switch on core {}", core_id);

                let current_ctx = get_context(*current_domain, core);
                let next_ctx = get_context(domain, core);
                let next_domain = get_domain(domain);
                switch_domain(vcpu, current_ctx, next_ctx, next_domain)
                    .expect("Failed to perform the switch");

                // Set switch return values
                vcpu.set(Register::Rax, 0);
                vcpu.set(Register::Rdi, return_capa.as_u64());

                // Update the current domain and context handle
                *current_domain = domain;
            }
            CoreUpdate::Trap {
                manager,
                trap,
                info,
            } => {
                log::trace!("Trap {} on core {}", trap, core_id);
                log::debug!(
                    "Exception Bitmap is {:b}",
                    vcpu.get_exception_bitmap().expect("Failed to read bitmpap")
                );

                let current_ctx = get_context(*current_domain, core);
                let next_ctx = get_context(manager, core);
                let next_domain = get_domain(manager);
                switch_domain(vcpu, current_ctx, next_ctx, next_domain)
                    .expect("Failed to perform switch for trap");

                log::debug!(
                    "Exception {} (bit shift {}) triggers switch from {:?} to {:?}",
                    trap,
                    Trapnr::from_u64(trap),
                    current_domain,
                    manager
                );

                // Inject exception now.
                let interrupt = VmExitInterrupt::from_info(info);
                log::debug!("The info to inject: {:b}", interrupt.as_u32(),);

                // We rewrite the value because it is cleared on every VM exit.
                vcpu.inject_interrupt(interrupt)
                    .expect("Unable to inject an exception");

                // Set parameters
                // TODO this could be a way to signal an error.
                //vcpu.set(Register::Rax, trap);

                // Update the current domain
                *current_domain = manager;
            }
            CoreUpdate::UpdateTrap { bitmap } => {
                log::trace!("Updating trap bitmap on core {} to {:b}", core_id, bitmap);
                let value = bitmap as u32;
                //TODO: for the moment we only offer interposition on the hardware cpu exception
                //interrupts (first 32 values).
                //By instrumenting APIC and virtualizing it, we might manage to do better in the
                //future.
                vcpu.set_exception_bitmap(ExceptionBitmap::from_bits_truncate(value))
                    .expect("Error setting the exception bitmap");
            }
        }
    }
}

fn switch_domain(
    vcpu: &mut ActiveVmcs<'static>,
    mut current_ctx: MutexGuard<ContextData>,
    next_ctx: MutexGuard<ContextData>,
    next_domain: MutexGuard<DomainData>,
) -> Result<(), CapaError> {
    // Safety check that both contexts have a valid vmcs.
    if current_ctx.vmcs.is_invalid() || next_ctx.vmcs.is_invalid() {
        log::error!(
            "VMCS are none during switch: curr:{:?}, next:{:?}",
            current_ctx.vmcs.is_invalid(),
            next_ctx.vmcs.is_invalid()
        );
        return Err(CapaError::InvalidSwitch);
    }
    if current_ctx.vmcs != next_ctx.vmcs {
        current_ctx.save(vcpu);
        next_ctx.restore(vcpu);
    } else {
        current_ctx.save_partial(vcpu);
        next_ctx.restore_partial(vcpu);
    }

    vcpu.set_ept_ptr(HostPhysAddr::new(
        next_domain.ept.unwrap().as_usize() | EPT_ROOT_FLAGS,
    ))
    .expect("Failed to update EPT");
    Ok(())
}

fn create_domain(domain: Handle<Domain>) {
    let mut domain = get_domain(domain);
    let allocator = allocator();
    if let Some(ept) = domain.ept {
        unsafe { free_ept(ept, allocator) };
    }

    let ept_root = allocator
        .allocate_frame()
        .expect("Failled to allocate EPT root")
        .zeroed();
    domain.ept = Some(ept_root.phys_addr);
}

fn revoke_domain(_domain: Handle<Domain>) {
    // Noop for now, might need to send IPIs once we land multi-core
}

fn update_domain_ept(
    domain_handle: Handle<Domain>,
    engine: &mut MutexGuard<CapaEngine>,
    init: bool,
) -> bool {
    let mut domain = get_domain(domain_handle);
    let allocator = allocator();
    let ept_root = allocator
        .allocate_frame()
        .expect("Failled to allocate EPT root")
        .zeroed();
    let mut mapper = EptMapper::new(
        allocator.get_physical_offset().as_usize(),
        ept_root.phys_addr,
    );

    for range in engine.get_domain_permissions(domain_handle).unwrap() {
        if !range.ops.contains(MemOps::READ) {
            log::error!("there is a region without read permission: {}", range);
            continue;
        }
        let mut flags = EptEntryFlags::READ;
        if range.ops.contains(MemOps::WRITE) {
            flags |= EptEntryFlags::WRITE;
        }
        if range.ops.contains(MemOps::EXEC) {
            if range.ops.contains(MemOps::SUPER) {
                flags |= EptEntryFlags::SUPERVISOR_EXECUTE;
            } else {
                flags |= EptEntryFlags::USER_EXECUTE;
            }
        }
        mapper.map_range(
            allocator,
            GuestPhysAddr::new(range.start),
            HostPhysAddr::new(range.start),
            range.size(),
            flags,
        )
    }

    if !init {
        loop {
            match TLB_FLUSH[domain_handle.idx()].compare_exchange(
                false,
                true,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(false) => break,
                _ => continue,
            }
        }
    }

    // The core needs exclusive access before updating the domain's EPT. Otherwise, we might have
    // miss freeing some EPT roots.
    domain.ept_old = domain.ept;
    domain.ept = Some(ept_root.phys_addr);

    true
}

fn notify_cores(core_id: usize, domain_core_bitmap: u64) {
    // initialize lapic
    for core in BitmapIterator::new(domain_core_bitmap) {
        if core == core_id {
            continue;
        }
        // send ipi
        let apic_id = apic::ApicId::XApic(core as u8);
        unsafe {
            apic::ipi_init(apic_id);
        }
    }
}

fn update_domain_iopt(domain_handle: Handle<Domain>, engine: &mut MutexGuard<CapaEngine>) -> bool {
    let mut domain = get_domain(domain_handle);
    let allocator = allocator();
    if let Some(iopt) = domain.iopt {
        unsafe { free_iopt(iopt, allocator) };
        // TODO: global invalidate context cache, PASID cache, and flush the IOTLB
    }

    let iopt_root = allocator
        .allocate_frame()
        .expect("Failed to allocate I/O PT root")
        .zeroed();
    let mut iopt_mapper = IoPtMapper::new(
        allocator.get_physical_offset().as_usize(),
        iopt_root.phys_addr,
    );

    // Traverse all regions of the I/O domain and maps them into the new iopt
    for range in engine.get_domain_permissions(domain_handle).unwrap() {
        if !range.ops.contains(MemOps::READ) {
            log::error!("there is a region without read permission: {}", range);
            continue;
        }
        let gpa = range.start;
        iopt_mapper.map_range(
            allocator,
            GuestPhysAddr::new(gpa),
            HostPhysAddr::new(range.start),
            range.size(),
            IoPtFlag::READ | IoPtFlag::WRITE | IoPtFlag::EXECUTE,
        )
    }

    domain.iopt = Some(iopt_root.phys_addr);

    // Update the IOMMU
    // TODO: @yuchen ideally we only need to change the 2nd stage page translation pointer on the
    //               context table, instead of reallocating the whole root table
    // Remap the DMA region on IOMMU
    let mut iommu = IOMMU.lock();
    let root_addr: HostPhysAddr = vtd::setup_iommu_context(iopt_mapper.get_root(), allocator);
    iommu.set_root_table_addr(root_addr.as_u64() | (0b00 << 10)); // Set legacy mode
    iommu.update_root_table_addr();
    iommu.enable_translation();
    log::info!("I/O MMU: {:?}", iommu.get_global_status());
    log::warn!("I/O MMU Fault: {:?}", iommu.get_fault_status());

    false
}

fn update_permission(
    domain_handle: Handle<Domain>,
    engine: &mut MutexGuard<CapaEngine>,
    init: bool,
) -> bool {
    if engine[domain_handle].is_io() {
        update_domain_iopt(domain_handle, engine)
    } else {
        update_domain_ept(domain_handle, engine, init)
    }
}

unsafe fn free_ept(ept: HostPhysAddr, allocator: &impl FrameAllocator) {
    let mapper = EptMapper::new(allocator.get_physical_offset().as_usize(), ept);
    mapper.free_all(allocator);
}

unsafe fn free_iopt(iopt: HostPhysAddr, allocator: &impl FrameAllocator) {
    let mapper = IoPtMapper::new(allocator.get_physical_offset().as_usize(), iopt);
    mapper.free_all(allocator);
}

// ———————————————————————————————— Display ————————————————————————————————— //

impl core::fmt::Display for CoreUpdate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CoreUpdate::TlbShootdown => write!(f, "TLB Shootdown"),
            CoreUpdate::Switch { domain, .. } => write!(f, "Switch({})", domain),
            CoreUpdate::Trap {
                manager,
                trap: interrupt,
                info: inf,
            } => {
                write!(f, "Trap({}, {} | {:b})", manager, interrupt, inf)
            }
            CoreUpdate::UpdateTrap { bitmap } => {
                write!(f, "UpdateTrap({:b})", bitmap)
            }
        }
    }
}
