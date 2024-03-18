//! Architecture specific monitor state, independant of the CapaEngine.

use core::sync::atomic::{AtomicBool, Ordering};

use attestation::signature::EnclaveReport;
use capa_engine::config::{NB_CORES, NB_DOMAINS, NB_REMAP_REGIONS};
use capa_engine::utils::BitmapIterator;
use capa_engine::{
    permission, AccessRights, Bitmaps, Buffer, CapaEngine, CapaError, CapaInfo, Domain, GenArena,
    Handle, LocalCapa, MemOps, NextCapaToken, Remapper, MEMOPS_ALL,
};
use mmu::eptmapper::EPT_ROOT_FLAGS;
use mmu::{EptMapper, FrameAllocator, IoPtFlag, IoPtMapper};
use spin::barrier::Barrier;
use spin::{Mutex, MutexGuard};
use stage_two_abi::{GuestInfo, Manifest};
use utils::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};
use vmx::bitmaps::EptEntryFlags;
use vmx::fields::{GeneralPurposeField, VmcsField, REGFILE_SIZE};
use vmx::{ActiveVmcs, VmExitInterrupt, Vmxon};
use vtd::Iommu;

use super::context::{
    Cache, Context16x86, Context32x86, Context64x86, ContextGpx86, ContextNatx86, Contextx86,
    DirtyRegGroups,
};
use super::filtered_fields::FilteredFields;
use super::guest::VmxState;
use super::init::NB_BOOTED_CORES;
use super::vmx_helper::{dump_host_state, load_host_state};
use super::{cpuid, vmx_helper};
use crate::allocator::{allocator, PAGE_SIZE};
use crate::attestation_domain::{attest_domain, calculate_attestation_hash};
use crate::rcframe::{RCFrame, RCFramePool, EMPTY_RCFRAME};
// ————————————————————————— Statics & Backend Data ————————————————————————— //

static CAPA_ENGINE: Mutex<CapaEngine> = Mutex::new(CapaEngine::new());
static IO_DOMAIN: Mutex<Option<LocalCapa>> = Mutex::new(None);
static INITIAL_DOMAIN: Mutex<Option<Handle<Domain>>> = Mutex::new(None);
static DOMAINS: [Mutex<DomainData>; NB_DOMAINS] = [EMPTY_DOMAIN; NB_DOMAINS];
static CORE_UPDATES: [Mutex<Buffer<CoreUpdate>>; NB_CORES] = [EMPTY_UPDATE_BUFFER; NB_CORES];
static CONTEXTS: [[Mutex<Contextx86>; NB_CORES]; NB_DOMAINS] = [EMPTY_CONTEXT_ARRAY; NB_DOMAINS];
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
    remapper: Remapper<NB_REMAP_REGIONS>,
}

const EMPTY_DOMAIN: Mutex<DomainData> = Mutex::new(DomainData {
    ept: None,
    ept_old: None,
    iopt: None,
    remapper: Remapper::new(),
});
const EMPTY_UPDATE_BUFFER: Mutex<Buffer<CoreUpdate>> = Mutex::new(Buffer::new());
const EMPTY_CONTEXT: Mutex<Contextx86> = Mutex::new(Contextx86 {
    dirty: Cache::<{ DirtyRegGroups::size() }> { bitmap: 0 },
    vmcs_16: [0; Context16x86::size()],
    dirty_16: Cache::<{ Context16x86::size() }> { bitmap: 0 },
    vmcs_32: [0; Context32x86::size()],
    dirty_32: Cache::<{ Context32x86::size() }> { bitmap: 0 },
    vmcs_64: [0; Context64x86::size()],
    dirty_64: Cache::<{ Context64x86::size() }> { bitmap: 0 },
    vmcs_nat: [0; ContextNatx86::size()],
    dirty_nat: Cache::<{ ContextNatx86::size() }> { bitmap: 0 },
    vmcs_gp: [0; ContextGpx86::size()],
    dirty_gp: Cache::<{ ContextGpx86::size() }> { bitmap: 0 },
    interrupted: false,
    vmcs: Handle::<RCFrame>::new_invalid(),
});
const EMPTY_CONTEXT_ARRAY: [Mutex<Contextx86>; NB_CORES] = [EMPTY_CONTEXT; NB_CORES];
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
                end: manifest.poffset as usize,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    // Call the remapper information.
    {
        let mut dom_dat = get_domain(domain);
        let _ = dom_dat
            .remapper
            .map_range(0, 0, manifest.iommu as usize, 1)
            .unwrap();
        let s = (manifest.iommu + PAGE_SIZE) as usize;
        let _ = dom_dat
            .remapper
            .map_range(s, s, (manifest.poffset as usize) - s, 1)
            .unwrap();
    }
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

pub fn get_context(domain: Handle<Domain>, core: usize) -> MutexGuard<'static, Contextx86> {
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

pub fn do_configure_core(
    current: Handle<Domain>,
    domain: LocalCapa,
    core: usize,
    idx: usize,
    value: usize,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let local_capa = domain;
    let domain = engine.get_domain_capa(current, domain)?;

    //TODO(aghosn): check how we could differentiate between registers
    //that can be changed and others. For the moment allow modifications
    //post sealing too.
    // Check the domain is not seal.
    /*if engine.is_sealed(domain) {
        return Err(CapaError::AlreadySealed);
    }*/

    // Check this is a valid core for the operation.
    let core_map = engine.get_domain_config(domain, Bitmaps::CORE);
    if (1 << core) & core_map == 0 {
        log::error!(
            "Invalid core {} for coremap {:b} in configure core",
            1 << core,
            core_map
        );
        return Err(CapaError::InvalidCore);
    }

    // Check this is a valid idx for a field.
    if !FilteredFields::is_valid(idx, true) {
        log::error!("Attempt to set an invalid register: {:x}", idx);
        return Err(CapaError::InvalidOperation);
    }
    let field = VmcsField::from_u32(idx as u32).unwrap();
    if field == VmcsField::ExceptionBitmap {
        engine
            .set_child_config(current, local_capa, Bitmaps::TRAP, !(value as u64))
            .expect("Unable to set the bitmap");
    }

    let mut target_ctxt = get_context(domain, core);
    if target_ctxt.vmcs.is_invalid() {
        log::error!("Target VMCS is none.");
        return Err(CapaError::InvalidOperation);
    }
    target_ctxt
        .set(field, value, None)
        .map_err(|_| CapaError::InvalidOperation)?;
    Ok(())
}

pub fn do_get_config_core(
    current: Handle<Domain>,
    domain: LocalCapa,
    core: usize,
    idx: usize,
) -> Result<usize, CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.get_domain_capa(current, domain)?;

    // Check the domain is not seal.
    //TODO(aghosn) we will need a way to differentiate between what's readable
    //and what's not readable once the domain is sealed.
    /*if engine.is_sealed(domain) {
        return Err(CapaError::AlreadySealed);
    }*/

    // Check this is a valid core for the operation.
    let core_map = engine.get_domain_config(domain, Bitmaps::CORE);
    if (1 << core) & core_map == 0 {
        return Err(CapaError::InvalidCore);
    }

    // Check this is a valid idx for a field.
    if !FilteredFields::is_valid(idx, false) {
        log::error!("Attempt to get an invalid register: {:x}", idx);
        return Err(CapaError::InvalidOperation);
    }
    let field = VmcsField::from_u32(idx as u32).unwrap();
    let mut target_ctx = get_context(domain, core);
    if target_ctx.vmcs.is_invalid() {
        log::error!("Target VMCS is invalid.");
        return Err(CapaError::InvalidOperation);
    }
    target_ctx
        .get(field, None)
        .map_err(|_| CapaError::InvalidOperation)
}

pub fn do_get_all_gp(
    current: Handle<Domain>,
    domain: LocalCapa,
    core: usize,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.get_domain_capa(current, domain)?;
    let core_map = engine.get_domain_config(domain, Bitmaps::CORE);
    if (1 << core) & core_map == 0 {
        return Err(CapaError::InvalidCore);
    }

    let mut curr_ctx = get_context(current, core);
    let tgt_ctx = get_context(domain, core);
    if curr_ctx.vmcs.is_invalid() || tgt_ctx.vmcs.is_invalid() {
        log::error!(
            "VMCs are none during a configure core {}: curr:{:?}, tgt:{:?}",
            core,
            curr_ctx.vmcs.is_invalid(),
            tgt_ctx.vmcs.is_invalid()
        );
        return Err(CapaError::InvalidOperation);
    }
    // Copy the general purpose registers.
    curr_ctx.vmcs_gp[0..REGFILE_SIZE - 1].copy_from_slice(&tgt_ctx.vmcs_gp[0..REGFILE_SIZE - 1]);
    Ok(())
}

pub fn do_set_all_gp(current: Handle<Domain>, domain: LocalCapa) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.get_domain_capa(current, domain)?;
    let core = cpuid();

    let core_map = engine.get_domain_config(domain, Bitmaps::CORE);
    if (1 << core) & core_map == 0 {
        return Err(CapaError::InvalidCore);
    }

    let curr_ctx = get_context(current, core);
    let mut tgt_ctx = get_context(domain, core);
    if curr_ctx.vmcs.is_invalid() || tgt_ctx.vmcs.is_invalid() {
        log::error!(
            "VMCs are none during a configure core {}: curr:{:?}, tgt:{:?}",
            core,
            curr_ctx.vmcs.is_invalid(),
            tgt_ctx.vmcs.is_invalid()
        );
        return Err(CapaError::InvalidOperation);
    }
    // Copy the general purpose registers.
    let rax = tgt_ctx.vmcs_gp[GeneralPurposeField::Rax as usize];
    let rdi = tgt_ctx.vmcs_gp[GeneralPurposeField::Rdi as usize];
    tgt_ctx.vmcs_gp[0..REGFILE_SIZE - 1].copy_from_slice(&curr_ctx.vmcs_gp[0..REGFILE_SIZE - 1]);
    tgt_ctx.vmcs_gp[GeneralPurposeField::Rax as usize] = rax;
    tgt_ctx.vmcs_gp[GeneralPurposeField::Rdi as usize] = rdi;
    Ok(())
}

pub fn do_set_fields(
    current: Handle<Domain>,
    domain: LocalCapa,
    core: usize,
    values: &[(usize, usize); 6],
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    // Check the core.
    let domain = engine.get_domain_capa(current, domain)?;
    let core_map = engine.get_domain_config(domain, Bitmaps::CORE);
    if (1 << core) & core_map == 0 {
        log::error!("Trying to set registers on the wrong core.");
        return Err(CapaError::InvalidCore);
    }
    // Get and set the context.
    let mut tgt_ctx = get_context(domain, core);
    if tgt_ctx.vmcs.is_invalid() {
        log::error!("The VMCS is none on core {}", core);
        return Err(CapaError::InvalidOperation);
    }
    for p in values {
        let field = p.0;
        let value = p.1;
        if field == !(0 as usize) {
            // We are done.
            break;
        }
        if !FilteredFields::is_valid(field, true) {
            log::error!("Invalid set field value: {:x}", field);
            return Err(CapaError::InvalidOperation);
        }
        let field = VmcsField::from_u32(field as u32).unwrap();
        tgt_ctx.set(field, value, None).unwrap();
        if field == VmcsField::ExceptionBitmap {
            engine
                .set_domain_config(domain, Bitmaps::TRAP, !(value as u64))
                .expect("Bitmap failure");
        }
    }
    Ok(())
}

pub fn do_init_child_context(
    current: Handle<Domain>,
    domain: LocalCapa,
    core: usize,
    vcpu: &mut ActiveVmcs<'static>,
    vmxon: &Vmxon,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine
        .get_domain_capa(current, domain)
        .expect("Unable to access child");
    let allocator = allocator();
    let max_cpus = NB_BOOTED_CORES.load(core::sync::atomic::Ordering::SeqCst) + 1;
    let mut rcvmcs = RC_VMCS.lock();
    let cores = engine.get_domain_config(domain, Bitmaps::CORE);
    // Check whether the domain is allowed on that core.
    if core > max_cpus || (1 << core) & cores == 0 {
        log::error!("Attempt to set context on unallowed core.");
        return Err(CapaError::InvalidCore);
    }
    let dest = &mut get_context(domain, core);
    let frame = allocator
        .allocate_frame()
        .expect("Unable to allocate frame");
    let rc = RCFrame::new(frame);
    dest.vmcs = rcvmcs.allocate(rc).expect("Unable to allocate rc frame");
    //Init the frame, it needs the identifier.
    vmxon.init_frame(frame);
    // Init the host state:
    {
        let current_ctxt = get_context(current, cpuid());
        let mut values: [usize; 13] = [0; 13];
        dump_host_state(vcpu, &mut values).or(Err(CapaError::InvalidSwitch))?;

        //TODO(aghosn): we could just set it in the context if we were able to distinguish
        //writable by tyche from writable by parent.

        // Switch to the target frame.
        vcpu.switch_frame(rcvmcs.get(dest.vmcs).unwrap().frame)
            .unwrap();

        // Init to the default values.
        let info: GuestInfo = Default::default();
        vmx_helper::default_vmcs_config(vcpu, &info, false);

        // Load the default values.
        load_host_state(vcpu, &mut values).or(Err(CapaError::InvalidSwitch))?;

        // Switch back the frame.
        vcpu.switch_frame(rcvmcs.get(current_ctxt.vmcs).unwrap().frame)
            .unwrap();
    }
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
    is_shared: bool,
    start: usize,
    end: usize,
    prot: usize,
) -> Result<(LocalCapa, LocalCapa), CapaError> {
    let prot = MemOps::from_usize(prot)?;
    let mut engine = CAPA_ENGINE.lock();
    let access = AccessRights {
        start,
        end,
        ops: prot,
    };
    let to_send = if is_shared {
        engine.alias_region(current, capa, access)?
    } else {
        engine.carve_region(current, capa, access)?
    };
    let to_revoke = engine.create_revoke_capa(current, to_send)?;
    apply_updates(&mut engine);
    Ok((to_send, to_revoke))
}

pub fn do_send(current: Handle<Domain>, capa: LocalCapa, to: LocalCapa) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    // Send is not allowed for region capa.
    // Use do_send_region instead.
    match engine.get_region_capa(current, capa)? {
        Some(_) => return Err(CapaError::InvalidCapa),
        _ => {}
    }
    engine.send(current, capa, to)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_send_region(
    current: Handle<Domain>,
    capa: LocalCapa,
    to: LocalCapa,
    alias: usize,
    is_repeat: bool,
    size: usize,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    // Get the capa first.
    let region_info = engine
        .get_region_capa(current, capa)?
        .ok_or(CapaError::InvalidCapa)?
        .get_access_rights();
    let repeat = {
        if is_repeat {
            let region_size = region_info.end - region_info.start;
            if size == 0 || (size % region_size) != 0 {
                return Err(CapaError::InvalidValue);
            }
            size / region_size
        } else {
            // Not a repeat, spans the entire thing.
            1
        }
    };

    // Check for an overlap first.
    {
        let target = engine.get_domain_capa(current, to)?;
        let dom_dat = get_domain(target);
        if dom_dat
            .remapper
            .overlaps(alias, repeat * (region_info.end - region_info.start))
        {
            return Err(CapaError::AlreadyAliased);
        }
    }

    let _ = engine.send(current, capa, to)?;
    // We cannot hold the reference while apply_updates is called.
    {
        let target = engine.get_domain_capa(current, to)?;
        let mut dom_dat = get_domain(target);
        let _ = dom_dat
            .remapper
            .map_range(
                region_info.start,
                alias,
                region_info.end - region_info.start,
                repeat,
            )
            .unwrap(); // Overlap is checked again but should not be triggered.
        engine.conditional_permission_update(target);
    };
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

pub fn do_revoke_region(
    current: Handle<Domain>,
    capa: LocalCapa,
    to: LocalCapa,
    alias: usize,
    size: usize,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    //TODO(aghosn): this is not really safe. We should make more checks.
    //Maybe have a cleaner interface for that after the rebuttal.
    {
        //Unmap the gpa range.
        let dom = engine.get_domain_capa(current, to).unwrap();
        let mut dom_dat = get_domain(dom);
        let _ = dom_dat.remapper.unmap_gpa_range(alias, size).unwrap();
    }
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

        log::info!("Domain {}", domain.idx());
        let mut next_capa = NextCapaToken::new();
        while let Some((info, next_next_capa)) = engine.enumerate(domain, next_capa) {
            next_capa = next_next_capa;
            log::info!(" - {}", info);
        }
        log::info!(
            "tracker: {}",
            engine.get_domain_regions(domain).expect("Invalid domain")
        );
        let dom_dat = get_domain(domain);
        log::info!("remaps {}", dom_dat.remapper.iter_segments());
        let remap = dom_dat
            .remapper
            .remap(engine.get_domain_permissions(domain).unwrap());
        log::info!("remapped: {}", remap);
    }
}

#[allow(dead_code)]
pub fn do_debug_addr(dom: Handle<Domain>, addr: usize) {
    log::info!("do_debug_addr:");
    let domain = get_domain(dom);
    let allocator = allocator();
    let mut mapper = EptMapper::new(
        allocator.get_physical_offset().as_usize(),
        domain.ept.unwrap(),
    );
    mapper.debug_range(GuestPhysAddr::new(addr), 0x10000);
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

#[allow(dead_code)]
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

pub fn do_handle_violation(current: Handle<Domain>) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let core = cpuid();
    {
        let mut current_ctx = get_context(current, core);
        current_ctx.interrupted = true;
    }
    engine.handle_violation(current, core)?;
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
}

fn post_ept_update(core_id: usize, cores: u64, domain: &Handle<Domain>) {
    let core_cnt = cores.count_ones();
    log::trace!(
        "core{}: post_ept_update with core_cnt={}",
        cpuid(),
        core_cnt
    );

    // Only the initiating core have access to this routine after gaining the atomic boolean
    // variable. All of the operations here are serialized until the point we release the atomic
    // boolean
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
    let new_epts = {
        let domain = get_domain(*domain);
        domain.ept.unwrap().as_usize()
    };
    for core in BitmapIterator::new(cores) {
        let mut context = get_context(*domain, core);
        context
            .set(VmcsField::EptPointer, new_epts | EPT_ROOT_FLAGS, None)
            .unwrap();
    }
    // We're done with the current TLB flush update
    log::trace!("core {} allows more TLB flushes", core_id);
    TLB_FLUSH[domain.idx()].store(false, Ordering::SeqCst);
}

fn push_core_update(core: usize) {
    log::trace!("cpu {} pushes Tlbshootdown to core={}", cpuid(), core);
    let mut core_updates = CORE_UPDATES[core as usize].lock();
    core_updates.push(CoreUpdate::TlbShootdown).unwrap();
}

/// General updates, containing both global updates on the domain's states, and core specific
/// updates that must be routed to the different cores.
fn apply_updates(engine: &mut MutexGuard<CapaEngine>) {
    while let Some(update) = engine.pop_update() {
        log::trace!("Update: {}", update);
        match update {
            // Updates that can be handled locally
            capa_engine::Update::PermissionUpdate { domain, core_map } => {
                let core_id = cpuid();
                log::trace!(
                    "cpu {} processes PermissionUpdate with core_map={:b}",
                    core_id,
                    core_map
                );
                let ept_update = update_permission(domain, engine);
                if ept_update {
                    log::trace!(
                        "cpu {} pushes core update with core_map={:b}",
                        cpuid(),
                        core_map
                    );
                    // Push TlbShootdown directly into the per-core queue
                    for core in BitmapIterator::new(core_map) {
                        push_core_update(core);
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
                core_updates
                    .push(CoreUpdate::Switch {
                        domain,
                        return_capa,
                    })
                    .unwrap();
            }
            capa_engine::Update::Trap {
                manager,
                trap,
                info,
                core,
            } => {
                let mut core_updates = CORE_UPDATES[core as usize].lock();
                core_updates
                    .push(CoreUpdate::Trap {
                        manager,
                        trap,
                        info,
                    })
                    .unwrap();
            }
        }
    }
}

fn tlb_shootdown(core_id: usize, current_domain: &mut Handle<Domain>, vcpu: &mut ActiveVmcs) {
    log::trace!("EPT Root update on core {}", core_id);
    // Reload the EPTs
    let domain = get_domain(*current_domain);
    log::trace!(
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

                let mut current_ctx = get_context(*current_domain, core);
                let mut next_ctx = get_context(domain, core);
                let next_domain = get_domain(domain);
                switch_domain(
                    vcpu,
                    &mut current_ctx,
                    &mut next_ctx,
                    next_domain,
                    return_capa,
                )
                .expect("Failed to perform the switch");
                // Update the current domain and context handle
                *current_domain = domain;
            }
            CoreUpdate::Trap {
                manager: _manager,
                trap,
                info: _info,
            } => {
                log::trace!("Trap {} on core {}", trap, core_id);
                log::debug!(
                    "Exception Bitmap is {:b}",
                    vcpu.get_exception_bitmap().expect("Failed to read bitmpap")
                );
                todo!("Update this code path.");

                /*let current_ctx = get_context(*current_domain, core);
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
                *current_domain = manager;*/
            }
        }
    }
}

fn switch_domain(
    vcpu: &mut ActiveVmcs<'static>,
    current_ctx: &mut MutexGuard<Contextx86>,
    next_ctx: &mut MutexGuard<Contextx86>,
    next_domain: MutexGuard<DomainData>,
    return_capa: LocalCapa,
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

    // We have different cases:
    // 1. current(interrupted) -- interrupt --> next.
    // 2. current -- resume interrupted --> next(interrupted)
    // 3. current -- synchronous --> next
    if current_ctx.interrupted && next_ctx.interrupted {
        panic!("Two domains should never be both interrupted in a switch.");
    }
    // Case 1: copy the interrupted state.
    if current_ctx.interrupted {
        next_ctx
            .copy_interrupt_frame(current_ctx, return_capa.as_usize(), vcpu)
            .unwrap();
    } else if next_ctx.interrupted {
        // Case 2: do not put the return capa.
        next_ctx.interrupted = false;
    } else {
        // Case 3: synchronous call.
        next_ctx.set(VmcsField::GuestRax, 0, None).unwrap();
        next_ctx
            .set(VmcsField::GuestRdi, return_capa.as_usize(), None)
            .unwrap();
    }

    // Now the logic for shared vs. private vmcs.
    if current_ctx.vmcs == next_ctx.vmcs {
        panic!("Why are the two vmcs the same?");
    }
    current_ctx.load(vcpu);
    next_ctx.switch_flush(&RC_VMCS, vcpu);

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

fn update_domain_ept(domain_handle: Handle<Domain>, engine: &mut MutexGuard<CapaEngine>) -> bool {
    let mut domain = get_domain(domain_handle);
    let allocator = allocator();
    if domain.ept_old.is_some() {
        panic!("We will replace an ept old that's not empty");
    }
    let ept_root = allocator
        .allocate_frame()
        .expect("Failled to allocate EPT root")
        .zeroed();
    let mut mapper = EptMapper::new(
        allocator.get_physical_offset().as_usize(),
        ept_root.phys_addr,
    );
    let permission_iter = engine.get_domain_permissions(domain_handle).unwrap();
    for range in domain.remapper.remap(permission_iter) {
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
            GuestPhysAddr::new(range.gpa),
            HostPhysAddr::new(range.hpa),
            range.size,
            flags,
        );
    }

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

    // The core needs exclusive access before updating the domain's EPT. Otherwise, we might have
    // miss freeing some EPT roots.
    // The contexts per core will be updated in the permission change update.
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
        x2apic::send_init_assert(core as u32)
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
    if iommu.get_addr() as usize != 0 {
        let root_addr: HostPhysAddr = vtd::setup_iommu_context(iopt_mapper.get_root(), allocator);
        iommu.set_root_table_addr(root_addr.as_u64() | (0b00 << 10)); // Set legacy mode
        iommu.update_root_table_addr();
        iommu.enable_translation();
        log::info!("I/O MMU: {:?}", iommu.get_global_status());
        log::warn!("I/O MMU Fault: {:?}", iommu.get_fault_status());
    }

    false
}

fn update_permission(domain_handle: Handle<Domain>, engine: &mut MutexGuard<CapaEngine>) -> bool {
    if engine[domain_handle].is_io() {
        update_domain_iopt(domain_handle, engine)
    } else {
        update_domain_ept(domain_handle, engine)
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
        }
    }
}
