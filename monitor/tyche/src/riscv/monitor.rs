//! Architecture specific monitor state

use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};

use attestation::hashing::TycheHasher;
use attestation::signature::EnclaveReport;
use capa_engine::config::{NB_CORES, NB_DOMAINS};
use capa_engine::utils::BitmapIterator;
use capa_engine::{
    permission, AccessRights, Bitmaps, Buffer, CapaEngine, CapaError, CapaInfo, Domain, Handle,
    LocalCapa, MemOps, NextCapaToken, MEMOPS_ALL,
};
use riscv_csrs::pmpcfg;
use riscv_pmp::csrs::{pmpaddr_csr_read, pmpaddr_csr_write, pmpcfg_csr_read, pmpcfg_csr_write};
use riscv_pmp::{
    clear_pmp, pmp_write_compute, PMPAddressingMode, PMPErrorCode, PMPWriteResponse,
    FROZEN_PMP_ENTRIES, PMP_CFG_ENTRIES, PMP_ENTRIES,
};
use riscv_sbi::ipi::aclint_mswi_send_ipi;
use riscv_utils::*;
use spin::{Mutex, MutexGuard};

use crate::arch::cpuid;
use crate::attestation_domain::{attest_domain, calculate_attestation_hash};
use crate::riscv::filtered_fields::RiscVField;

static CAPA_ENGINE: Mutex<CapaEngine> = Mutex::new(CapaEngine::new());
static INITIAL_DOMAIN: Mutex<Option<Handle<Domain>>> = Mutex::new(None);
static DOMAINS: [Mutex<DomainData>; NB_DOMAINS] = [EMPTY_DOMAIN; NB_DOMAINS];
static CONTEXTS: [[Mutex<ContextData>; NB_CORES]; NB_DOMAINS] = [EMPTY_CONTEXT_ARRAY; NB_DOMAINS];
static CORE_UPDATES: [Mutex<Buffer<CoreUpdate>>; NB_CORES] = [EMPTY_UPDATE_BUFFER; NB_CORES];

const ZERO: AtomicUsize = AtomicUsize::new(0);

static MONITOR_IPI_SYNC: [AtomicUsize; NUM_HARTS] = [ZERO; NUM_HARTS];

const XWR_PERM: usize = 7;

pub struct DomainData {
    data_init_done: bool,
    pmpaddr: [usize; PMP_ENTRIES],
    pmpcfg: [usize; PMP_CFG_ENTRIES],
}

pub struct ContextData {
    pub reg_state: RegisterState,
    pub satp: usize,
    pub mepc: usize,
    pub sp: usize,
    pub medeleg: usize,
}

const EMPTY_DOMAIN: Mutex<DomainData> = Mutex::new(DomainData {
    data_init_done: false,
    pmpaddr: [0; PMP_ENTRIES],
    pmpcfg: [0; PMP_CFG_ENTRIES],
});
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
    let hartid = cpuid();
    log::debug!("Creating initial domain.");
    let mut engine = CAPA_ENGINE.lock();
    let initial_domain = INITIAL_DOMAIN
        .lock()
        .expect("CapaEngine is not initialized yet");
    engine
        .start_domain_on_core(initial_domain, hartid)
        .expect("Failed to allocate initial domain");

    let domain = get_domain(initial_domain);
    if !domain.data_init_done {
        //update PMP permissions.
        log::debug!("Updating permissions for initial domain.");
        update_permission(initial_domain, &mut engine);
    }
    update_pmps(domain);

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
    if !RiscVField::is_valid(idx) {
        log::debug!("Attempt to set an invalid register: {:x}", idx);
        return Ok(());
    }
    let field = RiscVField::from_usize(idx).unwrap();
    //TODO @Neelu check that.
    /*if field == RiscVField::Medeleg {
        engine
            .set_child_config(current, local_capa, Bitmaps::TRAP, !(value as u64))
            .expect("Unable to set the bitmap");
    }*/

    let mut target_ctxt = get_context(domain, core);

    field.set(&mut target_ctxt, value);
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
    if !RiscVField::is_valid(idx) {
        log::debug!("Attempt to get an invalid register: {:x}", idx);
        return Ok(0);
    }
    let field = RiscVField::from_usize(idx).unwrap();
    let target_ctx = get_context(domain, core);
    Ok(field.get(&target_ctx))
}

pub fn do_set_field(
    current: Handle<Domain>,
    domain: LocalCapa,
    core: usize,
    field: usize,
    value: usize,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    // Check the core.
    let domain = engine.get_domain_capa(current, domain)?;
    let core_map = engine.get_domain_config(domain, Bitmaps::CORE);
    if (1 << core) & core_map == 0 {
        log::error!("Trying to set registers on the wrong core.");
        return Err(CapaError::InvalidCore);
    }
    if !RiscVField::is_valid(field) {
        log::debug!("Attempt to get an invalid field: {:x}", field);
        return Ok(());
    }
    let field = RiscVField::from_usize(field).unwrap();
    let mut target_ctx = get_context(domain, core);
    field.set(&mut target_ctx, value);
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
    log::debug!(
        "satp: {:x} mepc: {:x} sp: {:x} core {:x}",
        satp,
        mepc,
        sp,
        core
    );
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.get_domain_capa(current, domain)?;
    let cores = engine.get_domain_config(domain, Bitmaps::CORE);
    if (1 << core) & cores == 0 {
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
    // Use do_send_aliased instead.
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
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    // send_region is only allowed for region capa.
    match engine.get_region_capa(current, capa)? {
        Some(_) => {}
        _ => return Err(CapaError::InvalidCapa),
    }
    engine.send(current, capa, to)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_init_child_context(
    current: Handle<Domain>,
    domain: LocalCapa,
    core: usize,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.get_domain_capa(current, domain)?;

    // Check this is a valid core for the operation.
    let core_map = engine.get_domain_config(domain, Bitmaps::CORE);
    if (1 << core) & core_map == 0 {
        return Err(CapaError::InvalidCore);
    }
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

pub fn do_debug(engine: &mut MutexGuard<CapaEngine>) {
    //let mut engine = CAPA_ENGINE.lock();
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
    TlbShootdown {
        src_hartid: usize,
    },
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

fn apply_updates(engine: &mut MutexGuard<CapaEngine>) {
    while let Some(update) = engine.pop_update() {
        match update {
            capa_engine::Update::PermissionUpdate { domain, core_map } => {
                let src_hartid = cpuid();

                update_permission(domain, engine);

                if (1 << src_hartid) & core_map == 1 {
                    let mut domain_data = get_domain(domain);
                    update_pmps(domain_data);
                }

                for hart in BitmapIterator::new(core_map) {
                    if (hart != src_hartid) {
                        let mut per_hart_update_buffer = CORE_UPDATES[hart].lock();
                        per_hart_update_buffer.push(CoreUpdate::TlbShootdown { src_hartid });
                        drop(per_hart_update_buffer);
                        log::debug!(
                            "TLB Shootdown IPI from src_hartid: {} to dest_hartid: {}",
                            src_hartid,
                            hart
                        );
                        MONITOR_IPI_SYNC[src_hartid].fetch_add(1, Ordering::SeqCst);
                        aclint_mswi_send_ipi(hart);
                    }
                }

                while MONITOR_IPI_SYNC[src_hartid].load(Ordering::SeqCst) > 0 {
                    //TODO: Should I process local-core-updates here?
                    core::hint::spin_loop();
                }

                //When it's all done then just continue!
            }
            capa_engine::Update::RevokeDomain { domain } => revoke_domain(domain, engine),
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
            } //TODO: @Neelu might have bugs since we removed that.
              /*capa_engine::Update::UpdateTraps { trap, core } => {
                  let mut core_updates = CORE_UPDATES[core as usize].lock();
                  core_updates.push(CoreUpdate::UpdateTrap { bitmap: !trap });
              }*/
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
            CoreUpdate::TlbShootdown { src_hartid } => {
                log::debug!("TLB Shootdown on core {} from src {}", core_id, src_hartid);
                // Rewrite the PMPs
                let domain = get_domain(*current_domain);
                update_pmps(domain);
                MONITOR_IPI_SYNC[src_hartid].fetch_sub(1, Ordering::SeqCst);
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
                let mut next_ctx = get_context(domain, core);
                let next_domain = get_domain(domain);
                switch_domain(
                    current_domain,
                    current_ctx,
                    current_reg_state,
                    &mut next_ctx,
                    next_domain,
                    domain,
                );

                current_reg_state.a0 = 0x0;
                current_reg_state.a1 = return_capa.as_usize() as isize;
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
    current_domain: &mut Handle<Domain>,
    mut current_ctx: MutexGuard<ContextData>,
    current_reg_state: &mut RegisterState,
    next_ctx: &mut MutexGuard<ContextData>,
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

    // Propagate the state from the child, see drivers/tyche/src/domain.c exit frame.
    next_ctx.reg_state.a2 = current_ctx.mepc;
    next_ctx.reg_state.a3 = current_ctx.sp;
    next_ctx.reg_state.a4 = current_ctx.satp;
    next_ctx.reg_state.a5 = current_ctx.medeleg;
    *current_reg_state = next_ctx.reg_state;

    //IMP TODO: Toggling interrupts based on the assumption that we are running initial domain and
    //one more domain - This needs to be implemented for more generic cases via per core updates.
    toggle_supervisor_interrupts();

    if (next_domain.data_init_done) {
        update_pmps(next_domain);
    } else {
        panic!("THIS SHOULD NEVER HAPPEN!");
        let mut engine = CAPA_ENGINE.lock();
        update_permission(domain, &mut engine);
    }
}

fn create_domain(domain: Handle<Domain>) {
    //let mut domain = get_domain(domain);
    //Todo: Is there anything that needs to be done here?
    //
    //Also, in the x86 equivalent, what happens when EPT root fails to be allocated - Domain
    //creation fails? How is this reflected in the capa engine?
}

fn revoke_domain(_domain: Handle<Domain>, engine: &mut MutexGuard<CapaEngine>) {
    //Todo
}

fn update_pmps(domain: MutexGuard<DomainData>) {
    log::info!("Updating PMPs FOR REAL!");
    clear_pmp();
    for i in FROZEN_PMP_ENTRIES..PMP_ENTRIES {
        pmpaddr_csr_write(i, domain.pmpaddr[i]);
        log::trace!(
            "updating pmpaddr index: {}, val: {:x}",
            i,
            domain.pmpaddr[i]
        );
    }
    for i in 0..PMP_CFG_ENTRIES {
        pmpcfg_csr_write(i * 8, domain.pmpcfg[i]);
        log::trace!("updating pmpcfg index: {}, val: {:x}", i, domain.pmpcfg[i]);
    }
    unsafe {
        asm!("sfence.vma");
    }
}

fn update_permission(domain_handle: Handle<Domain>, engine: &mut MutexGuard<CapaEngine>) {
    let mut pmp_write_response: PMPWriteResponse;
    let mut pmp_index = FROZEN_PMP_ENTRIES;
    for range in engine.get_domain_permissions(domain_handle).unwrap() {
        if !range.ops.contains(MemOps::READ) {
            log::error!("there is a region without read permission: {}", range);
            continue;
        }
        //TODO: Update PMP based on specific permissions - just need to compute XWR using MemOps.
        log::trace!(
            "PMP Compute for Region: index: {:x} start: {:x} end: {:x}",
            pmp_index,
            range.start,
            range.start + range.size()
        );

        pmp_write_response = pmp_write_compute(pmp_index, range.start, range.size(), XWR_PERM);

        if pmp_write_response.write_failed {
            panic!("PMP Write Not Ok");
        } else {
            log::debug!("PMP Write Ok");

            if pmp_write_response.addressing_mode == PMPAddressingMode::NAPOT {
                log::trace!(
                    "NAPOT addr: {:x} cfg: {:x}",
                    pmp_write_response.addr1,
                    pmp_write_response.cfg1
                );
                update_domain_pmp(
                    domain_handle,
                    pmp_index,
                    pmp_write_response.addr1,
                    pmp_write_response.cfg1,
                );
                pmp_index = pmp_index + 1;
            } else if pmp_write_response.addressing_mode == PMPAddressingMode::TOR {
                log::trace!(
                    "TOR addr: {:x} cfg: {:x} addr: {:x} cfg: {:x}",
                    pmp_write_response.addr1,
                    pmp_write_response.cfg1,
                    pmp_write_response.addr2,
                    pmp_write_response.cfg2
                );
                update_domain_pmp(
                    domain_handle,
                    pmp_index,
                    pmp_write_response.addr1,
                    pmp_write_response.cfg1,
                );
                update_domain_pmp(
                    domain_handle,
                    pmp_index + 1,
                    pmp_write_response.addr2,
                    pmp_write_response.cfg2,
                );
                pmp_index = pmp_index + 2;
            }

            if pmp_index > PMP_ENTRIES {
                panic!("Cannot continue running this domain: PMPOverflow");
            }
        }
    }
    let mut domain = get_domain(domain_handle);
    domain.data_init_done = true;
}

fn update_domain_pmp(
    domain_handle: Handle<Domain>,
    pmp_index: usize,
    pmp_addr: usize,
    pmp_cfg: usize,
) {
    let mut domain = get_domain(domain_handle);
    let index_pos: usize = pmp_index % 8;
    domain.pmpcfg[pmp_index / 8] = domain.pmpcfg[pmp_index / 8] & !(0xff << (index_pos * 8));
    domain.pmpcfg[pmp_index / 8] = domain.pmpcfg[pmp_index / 8] | pmp_cfg;

    domain.pmpaddr[pmp_index] = pmp_addr;

    log::trace!(
        "Updated for DOMAIN: PMPCFG: {:x} PMPADDR: {:x} at index: {:x}",
        domain.pmpcfg[pmp_index / 8],
        domain.pmpaddr[pmp_index],
        pmp_index
    );
}

// ———————————————————————————————— Display ————————————————————————————————— //

impl core::fmt::Display for CoreUpdate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CoreUpdate::TlbShootdown { src_hartid } => write!(f, "TLB Shootdown({})", src_hartid),
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
