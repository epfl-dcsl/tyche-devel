//! Architecture specific monitor state

use attestation::hashing::TycheHasher;
use attestation::signature::EnclaveReport;
use capa_engine::config::{NB_CORES, NB_DOMAINS};
use capa_engine::{
    permission, AccessRights, Bitmaps, Buffer, CapaEngine, CapaError, CapaInfo, Domain, Handle,
    LocalCapa, MemOps, NextCapaToken, MEMOPS_ALL,
};
use riscv_csrs::pmpcfg;
use riscv_pmp::{
    clear_pmp, pmp_write, PMPAddressingMode, PMPErrorCode, FROZEN_PMP_ENTRIES, PMP_ENTRIES,
};
use riscv_utils::*;
use spin::{Mutex, MutexGuard};

//use crate::riscv::arch::write_medeleg;
use crate::arch::cpuid;
use crate::attestation_domain::{attest_domain, calculate_attestation_hash};

static CAPA_ENGINE: Mutex<CapaEngine> = Mutex::new(CapaEngine::new());
static INITIAL_DOMAIN: Mutex<Option<Handle<Domain>>> = Mutex::new(None);
static DOMAINS: [Mutex<DomainData>; NB_DOMAINS] = [EMPTY_DOMAIN; NB_DOMAINS];
static CONTEXTS: [[Mutex<ContextData>; NB_CORES]; NB_DOMAINS] = [EMPTY_CONTEXT_ARRAY; NB_DOMAINS];
static CORE_UPDATES: [Mutex<Buffer<CoreUpdate>>; NB_CORES] = [EMPTY_UPDATE_BUFFER; NB_CORES];

const XWR_PERM: usize = 7;

pub struct DomainData {
    //Todo
    //Add a PMP snapshot here, so PMP entries can be written directly without going
    //through the pmp_write function every time!
}

pub struct ContextData {
    pub reg_state: RegisterState,
    pub satp: usize,
    pub mepc: usize,
    pub sp: usize,
    pub medeleg: usize,
}

const EMPTY_DOMAIN: Mutex<DomainData> = Mutex::new(DomainData {}); //Todo Init the domain data
const EMPTY_UPDATE_BUFFER: Mutex<Buffer<CoreUpdate>> = Mutex::new(Buffer::new()); //once done.
const EMPTY_CONTEXT: Mutex<ContextData> = Mutex::new(ContextData {
    reg_state: RegisterState::const_default(),
    satp: 0,
    mepc: 0,
    sp: 0,
    medeleg: 0,
});
const EMPTY_CONTEXT_ARRAY: [Mutex<ContextData>; NB_CORES] = [EMPTY_CONTEXT; NB_CORES];

// ————————————————————————————— Initialization ————————————————————————————— //

pub fn init() {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.create_manager_domain(permission::ALL).unwrap();
    apply_updates(&mut engine);
    engine
        .create_root_region(
            domain,
            AccessRights {
                start: 0x80400000, //Linux Root Region Start Address
                end: 0x800000000, //17fffffff,   //Linux Root Region End Address - it's currently based on early
                //memory node range detected by linux.
                //TODO: It should be a part of the manifest.
                //TODO: Dom0 needs 2 regions - ram region and pcie-mmio region
                //(currently overprovisioning memory accesses)
                //(check memory tree in QEMU).
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    engine
        .create_root_region(
            domain,
            AccessRights {
                start: SIFIVE_TEST_SYSCON_BASE_ADDRESS,
                end: PCI_BASE_ADDRESS + PCI_SIZE, //Optimization: Including both PLIC and PCI regions in a single PMP
                //entry
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    apply_updates(&mut engine);

    // Save the initial domain
    let mut initial_domain = INITIAL_DOMAIN.lock();
    *initial_domain = Some(domain);
}

pub fn start_initial_domain_on_cpu() -> (Handle<Domain>) {
    let cpuid = cpuid();
    log::debug!("Creating initial domain.");
    let mut engine = CAPA_ENGINE.lock();
    let initial_domain = INITIAL_DOMAIN
        .lock()
        .expect("CapaEngine is not initialized yet");
    engine
        .start_domain_on_core(initial_domain, cpuid)
        .expect("Failed to allocate initial domain");

    //update PMP permissions.
    log::debug!("Updating permissions for initial domain.");
    update_permission(initial_domain, &mut engine);

    (initial_domain)
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

pub fn do_set_entry(
    current: Handle<Domain>,
    domain: LocalCapa,
    core: usize,
    satp: usize,
    mepc: usize,
    sp: usize,
) -> Result<(), CapaError> {
    log::debug!("satp: {:x} mepc: {:x} sp: {:x}", satp, mepc, sp);
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.get_domain_capa(current, domain)?;
    let cores = engine.get_domain_config(domain, Bitmaps::CORE);
    if (1 << core) & cores == 0 {
        //Neelu: TODO: Is it better to create a mask for this check?
        return Err(CapaError::InvalidCore);
    }
    let context = &mut get_context(domain, core);

    context.satp = ((satp >> 12) | PAGING_MODE_SV48);
    context.mepc = (mepc - 0x4); //TODO: Temporarily subtracting 4, because at the end of handle_exit,
                                 //mepc+4 is the address being returned to. Need to find an elegant way
                                 //to manage this.

    context.sp = sp;
    let temp_reg_state = RegisterState::const_default();
    context.reg_state = temp_reg_state;
    Ok(())
}

pub fn do_seal(current: Handle<Domain>, domain: LocalCapa) -> Result<LocalCapa, CapaError> {
    let cpuid = cpuid();
    let mut engine = CAPA_ENGINE.lock();
    let capa = engine.seal(current, cpuid, domain)?;

    if let Ok(domain_capa) = engine.get_domain_capa(current, domain) {
        log::trace!("Calculating attestation hash");
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

pub fn do_switch(
    current: Handle<Domain>,
    //current_ctx: Handle<Context>,
    capa: LocalCapa,
    cpuid: usize,
    current_reg_state: &mut RegisterState,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    engine.switch(current, cpuid, capa)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_debug() {
    let mut engine = CAPA_ENGINE.lock();
    let mut next = NextCapaToken::new();
    log::debug!("Logging domains.");
    while let Some((domain, next_next)) = engine.enumerate_domains(next) {
        next = next_next;

        log::debug!("Domain");
        let mut next_capa = NextCapaToken::new();
        while let Some((info, next_next_capa)) = engine.enumerate(domain, next_capa) {
            next_capa = next_next_capa;
            log::debug!(" - {}", info);
        }
        log::debug!("{}", engine.get_domain_regions(domain).unwrap());
    }
}

fn copy_array(dst: &mut [u8], src: &[u8], index: usize) {
    let mut ind_help = index;
    for x in src {
        dst[ind_help] = *x;
        ind_help += 1;
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

// ———————————————————————————————— Updates ————————————————————————————————— //

/// Per-core updates
#[derive(Debug, Clone, Copy)]
enum CoreUpdate {
    TlbShootdown,
    Switch {
        domain: Handle<Domain>,
        return_capa: LocalCapa,
        //current_reg_state: RegisterState,
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

fn apply_updates(engine: &mut MutexGuard<CapaEngine>) {
    while let Some(update) = engine.pop_update() {
        match update {
            capa_engine::Update::PermissionUpdate { domain, .. } => (),
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

/// Updates that must be applied to a given core.
pub fn apply_core_updates(
    current_domain: &mut Handle<Domain>,
    core_id: usize,
    current_reg_state: &mut RegisterState,
) {
    let core = cpuid();
    let mut update_queue = CORE_UPDATES[core_id].lock();
    while let Some(update) = update_queue.pop() {
        log::debug!("Core Update: {}", update);
        match update {
            CoreUpdate::TlbShootdown => {
                log::trace!("TLB Shootdown on core {}", core_id);

                // Rewrite the PMPs
                let mut engine = CAPA_ENGINE.lock();
                update_permission(*current_domain, &mut engine);
            }
            CoreUpdate::Switch {
                domain,
                return_capa,
                //current_reg_state,
            } => {
                log::debug!(
                    "Domain Switch on core {} for domain {}, return_capa: {:x}",
                    core_id,
                    domain,
                    return_capa.as_usize()
                );

                let current_ctx = get_context(*current_domain, core);
                let next_ctx = get_context(domain, core);
                let next_domain = get_domain(domain);
                switch_domain(
                    current_domain,
                    current_ctx,
                    current_reg_state,
                    next_ctx,
                    next_domain,
                    domain,
                );

                current_reg_state.a0 = 0x0;
                current_reg_state.a1 = return_capa.as_usize();
                *current_domain = domain;
            }
            CoreUpdate::Trap {
                manager,
                trap,
                info,
            } => {
                log::debug!("Trap {} on core {}", trap, core_id);
            }
            CoreUpdate::UpdateTrap { bitmap } => {
                log::debug!("Updating trap bitmap on core {} to {:b}", core_id, bitmap);
            }
        }
    }
}

fn switch_domain(
    //vcpu: &mut ActiveVmcs<'static>,
    current_domain: &mut Handle<Domain>,
    mut current_ctx: MutexGuard<ContextData>,
    current_reg_state: &mut RegisterState,
    next_ctx: MutexGuard<ContextData>,
    next_domain: MutexGuard<DomainData>,
    domain: Handle<Domain>,
) {
    log::debug!(
        "writing satp: {:x} mepc {:x} mscratch: {:x}",
        next_ctx.satp,
        next_ctx.mepc,
        next_ctx.sp
    );
    //Save current context
    current_ctx.reg_state = *current_reg_state;
    current_ctx.mepc = read_mepc();
    current_ctx.sp = read_mscratch(); //Recall that this is where the sp is saved.
    current_ctx.satp = read_satp();
    current_ctx.medeleg = read_medeleg();

    //Switch domain
    write_satp(next_ctx.satp);
    write_mscratch(next_ctx.sp);
    write_mepc(next_ctx.mepc);
    write_medeleg(next_ctx.medeleg); //TODO: This needs to be part of Trap/UpdateTrap.
    *current_reg_state = next_ctx.reg_state;

    //IMP TODO: Toggling interrupts based on the assumption that we are running initial domain and
    //one more domain - This needs to be implemented for more generic cases via per core updates.
    toggle_supervisor_interrupts();

    //TODO: Create a snapshot of the PMPCFG and PMPADDR values and store it as the DomainData
    //After that, instead of update_permission, something like apply_permission could be called to
    //directly write the PMP - no need to reiterate through the domain's regions as happens in
    //update_permission.

    let mut engine = CAPA_ENGINE.lock();
    update_permission(domain, &mut engine);
}

fn create_domain(domain: Handle<Domain>) {
    //let mut domain = get_domain(domain);
    //Todo: Is there anything that needs to be done here?
    //
    //Also, in the x86 equivalent, what happens when EPT root fails to be allocated - Domain
    //creation fails? How is this reflected in the capa engine?
}

fn revoke_domain(_domain: Handle<Domain>) {
    //Todo
}

//Neelu: TODO: Make this function create more of a cache/snapshot of PMP entries - and later apply
//it on switching or TLBShootDown to actually reflect in the PMP.
fn update_permission(domain_handle: Handle<Domain>, engine: &mut MutexGuard<CapaEngine>) {
    //Update PMPs

    //let mut domain = get_domain(domain_handle);
    //First clean current PMP settings - this should internally cause the appropriate flushes
    log::debug!("Clearing PMP");
    clear_pmp();
    let mut pmp_write_result: Result<PMPAddressingMode, PMPErrorCode>;
    let mut pmp_index = FROZEN_PMP_ENTRIES;
    for range in engine.get_domain_permissions(domain_handle).unwrap() {
        if !range.ops.contains(MemOps::READ) {
            log::error!("there is a region without read permission: {}", range);
            continue;
        }

        //TODO: Write to PMP based on specific permissions.
        /* let mut flags: usize = 1 << pmpcfg::READ;
        if range.ops.contains(MemOps::WRITE) {
            flags |= (1 << pmpcfg::WRITE);
        }
        if range.ops.contains(MemOps::EXEC) {
            flags |= (1 << pmpcfg::EXECUTE);

            //TODO: The U bit needs to be set in the page tables once the runtime is implemented.
            // if range.ops.contains(MemOps::SUPER) {
            //    flags |= EptEntryFlags::SUPERVISOR_EXECUTE;
            //} else {
            //    flags |= EptEntryFlags::USER_EXECUTE;
            //}
        } */

        log::debug!(
            "Protecting Domain: index: {:x} start: {:x} end: {:x}",
            pmp_index,
            range.start,
            range.start + range.size()
        );

        pmp_write_result = pmp_write(pmp_index, range.start, range.size(), XWR_PERM);
        //Check the PMP addressing mode so the index can be advanced by 1
        //(NAPOT) or 2 (TOR).
        if pmp_write_result.is_ok() {
            log::debug!("PMP write ok");

            if pmp_write_result.unwrap() == PMPAddressingMode::NAPOT {
                pmp_index = pmp_index + 1;
            } else if pmp_write_result.unwrap() == PMPAddressingMode::TOR {
                pmp_index = pmp_index + 2;
            }

            if pmp_index > PMP_ENTRIES {
                // TODO: PMPOverflow Handling
                // Panic for now.
                panic!("Cannot continue running this domain: PMPOverflow");
            }
        } else {
            log::debug!("PMP write NOT ok!");
            //Todo: Check error codes and manage appropriately.
        }
    }
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
