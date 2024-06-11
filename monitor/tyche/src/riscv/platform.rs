use core::arch::asm;
use core::sync::atomic::Ordering;

use capa_engine::utils::BitmapIterator;
use capa_engine::{
    permission, AccessRights, CapaEngine, CapaError, Domain, Handle, MemOps, MEMOPS_ALL,
};
use riscv_csrs::{mcause, *};
use riscv_pmp::{
    clear_pmp, pmp_write_compute, PMPAddressingMode, PMPErrorCode, PMPWriteResponse,
    FROZEN_PMP_ENTRIES, PMP_CFG_ENTRIES, PMP_ENTRIES,
};
use riscv_sbi::ecall::ecall_handler;
use riscv_sbi::ipi::{aclint_mswi_send_ipi, process_ipi};
use riscv_sbi::sbi::EXT_IPI;
use riscv_utils::*;
use spin::{Mutex, MutexGuard};

use crate::arch::cpuid;
use crate::monitor::{CoreUpdate, Monitor, PlatformState, CAPA_ENGINE, INITIAL_DOMAIN};
use crate::riscv::context::ContextRiscv;
use crate::riscv::filtered_fields::RiscVField;
use crate::riscv::state::{DataRiscv, StateRiscv, CONTEXTS, DOMAINS, MONITOR_IPI_SYNC};

// —————————————————————————— Constant and Globals —————————————————————————— //

const XWR_PERM: usize = 7;
const EMPTY_ACTIVE_DOMAIN: Mutex<Option<Handle<Domain>>> = Mutex::new(None);
static ACTIVE_DOMAIN: [Mutex<Option<Handle<Domain>>>; NUM_HARTS] = [EMPTY_ACTIVE_DOMAIN; NUM_HARTS];

// ————————————————————————— Platform specific code ————————————————————————— //

// M-mode trap handler
// Saves register state - calls trap_handler - restores register state - mret to intended mode.

#[repr(align(4))]
#[naked]
pub extern "C" fn machine_trap_handler() {
    unsafe {
        asm!(
            "csrrw sp, mscratch, sp
        addi sp, sp, -34*8
        sd ra, 0*8(sp)
        sd a0, 1*8(sp)
        sd a1, 2*8(sp)
        sd a2, 3*8(sp)
        sd a3, 4*8(sp)
        sd a4, 5*8(sp)
        sd a5, 6*8(sp)
        sd a6, 7*8(sp)
        sd a7, 8*8(sp)
        sd t0, 9*8(sp)
        sd t1, 10*8(sp)
        sd t2, 11*8(sp)
        sd t3, 12*8(sp)
        sd t4, 13*8(sp)
        sd t5, 14*8(sp)
        sd t6, 15*8(sp)
        sd zero, 16*8(sp)
        sd gp, 17*8(sp)
        sd tp, 18*8(sp)
        sd s0, 19*8(sp)
        sd s1, 20*8(sp)
        sd s2, 21*8(sp)
        sd s3, 22*8(sp)
        sd s4, 23*8(sp)
        sd s5, 24*8(sp)
        sd s6, 25*8(sp)
        sd s7, 26*8(sp)
        sd s8, 27*8(sp)
        sd s9, 28*8(sp)
        sd s10, 29*8(sp)
        sd s11, 30*8(sp)
        //csrr t1, mepc 
        //sd t1, 31*8(sp)
        //csrr t1, mstatus
        //sd t1, 32*8(sp)
        mv a0, sp      //arg to trap_handler
        auipc x1, 0x0
        addi x1, x1, 10
        j {trap_handler}
        //ld t1, 31*8(sp)
        //csrw mepc, t1
        ld ra, 0*8(sp)
        ld a0, 1*8(sp)
        ld a1, 2*8(sp)
        ld a2, 3*8(sp)
        ld a3, 4*8(sp)
        ld a4, 5*8(sp)
        ld a5, 6*8(sp)
        ld a6, 7*8(sp)
        ld a7, 8*8(sp)
        ld t0, 9*8(sp)
        ld t1, 10*8(sp)
        ld t2, 11*8(sp)
        ld t3, 12*8(sp)
        ld t4, 13*8(sp)
        ld t5, 14*8(sp)
        ld t6, 15*8(sp)
        ld zero, 16*8(sp)
        ld gp, 17*8(sp)
        ld tp, 18*8(sp)
        ld s0, 19*8(sp)
        ld s1, 20*8(sp)
        ld s2, 21*8(sp)
        ld s3, 22*8(sp)
        ld s4, 23*8(sp)
        ld s5, 24*8(sp)
        ld s6, 25*8(sp)
        ld s7, 26*8(sp)
        ld s8, 27*8(sp)
        ld s9, 28*8(sp)
        ld s10, 29*8(sp)
        ld s11, 30*8(sp)
        addi sp, sp, 34*8
        csrrw sp, mscratch, sp
        mret",
            trap_handler = sym MonitorRiscv::handle_exit,
            options(noreturn)
        )
    }
}

pub extern "C" fn exit_handler_failed(mcause: usize) {
    // TODO: Currently, interrupts must be getting redirected here too. Confirm this and then fix
    // it.
    panic!(
        "*******WARNING: Cannot handle this trap with mcause: {:x} !*******",
        mcause
    );
}

pub fn illegal_instruction_handler(
    mepc: usize,
    mtval: usize,
    mstatus: usize,
    mip: usize,
    mie: usize,
) {
    panic!(
        "Illegal Instruction Trap! mepc: {:x} mtval: {:x} mstatus: {:x} mip: {:x} mie: {:x}",
        mepc, mtval, mstatus, mip, mie
    );
}

// ———————————————————— Platform implementation of State ———————————————————— //

impl PlatformState for StateRiscv {
    type DomainData = DataRiscv;
    type Context = ContextRiscv;

    fn find_buff(
        engine: &MutexGuard<CapaEngine>,
        domain_handle: Handle<Domain>,
        addr: usize,
        end: usize,
    ) -> Option<usize> {
        todo!("Implement");
    }

    fn platform_init_io_mmu(&self, addr: usize) {
        todo!();
    }

    fn get_domain(domain: Handle<Domain>) -> MutexGuard<'static, Self::DomainData> {
        DOMAINS[domain.idx()].lock()
    }

    fn get_context(domain: Handle<Domain>, core: usize) -> MutexGuard<'static, Self::Context> {
        CONTEXTS[domain.idx()][core].lock()
    }

    fn remap_core(core: usize) -> usize {
        core
    }

    fn remap_core_bitmap(bitmap: u64) -> u64 {
        bitmap
    }

    fn max_cpus() -> usize {
        NUM_HARTS_AVAILABLE.load(Ordering::SeqCst)
    }

    fn create_context(
        &mut self,
        _engine: MutexGuard<CapaEngine>,
        current: Handle<Domain>,
        domain: Handle<Domain>,
        core: usize,
    ) -> Result<(), CapaError> {
        let ctx = &mut Self::get_context(domain, core);
        ctx.satp = 0;
        ctx.mepc = 0;
        ctx.sp = 0;
        ctx.medeleg = 0;
        ctx.reg_state = RegisterState::const_default();
        Ok(())
    }

    fn update_permission(
        domain_handle: Handle<Domain>,
        engine: &mut MutexGuard<CapaEngine>,
    ) -> bool {
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
                    Self::update_domain_pmp(
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
                    Self::update_domain_pmp(
                        domain_handle,
                        pmp_index,
                        pmp_write_response.addr1,
                        pmp_write_response.cfg1,
                    );
                    Self::update_domain_pmp(
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
        let mut domain = Self::get_domain(domain_handle);
        domain.data_init_done = true;
        true
    }

    fn create_domain(domain: Handle<Domain>) {
        //Todo: Is there anything that needs to be done here?
        //
        //Also, in the x86 equivalent, what happens when EPT root fails to be allocated - Domain
        //creation fails? How is this reflected in the capa engine?
    }

    fn revoke_domain(_domain: Handle<Domain>) {
        // Noop for now, might need to send IPIs once we land multi-core
    }

    fn apply_core_update(
        &mut self,
        current_domain: &mut Handle<Domain>,
        core_id: usize,
        update: &CoreUpdate,
    ) {
        log::debug!("Core Update: {}", update);
        match *update {
            CoreUpdate::TlbShootdown { src_core } => {
                log::debug!("TLB Shootdown on core {} from src {}", core_id, src_core);
                // Rewrite the PMPs
                let domain = StateRiscv::get_domain(*current_domain);
                Self::update_pmps(domain);
                MONITOR_IPI_SYNC[src_core].fetch_sub(1, Ordering::SeqCst);
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

                let current_ctx = &mut StateRiscv::get_context(*current_domain, core_id);
                let mut next_ctx = StateRiscv::get_context(domain, core_id);
                let next_domain = StateRiscv::get_domain(domain);
                //TODO: figure out what the original current_reg_state was.
                //Apparently taken from the handler. Let's ignore it.
                Self::switch_domain(
                    current_domain,
                    current_ctx,
                    //&mut current_ctx.reg_state,
                    //current_reg_state,
                    &mut next_ctx,
                    next_domain,
                    domain,
                );

                current_ctx.reg_state.a0 = 0x0;
                current_ctx.reg_state.a1 = return_capa.as_usize() as isize;
                *current_domain = domain;
            }
            CoreUpdate::Trap {
                manager,
                trap,
                info,
            } => {
                log::debug!("Trap {} on core {}", trap, core_id);
            }
        }
    }

    fn platform_shootdown(&mut self, domain: &Handle<Domain>, core: usize, trigger: bool) {
        let mut domain_data = Self::get_domain(*domain);
        Self::update_pmps(domain_data);
    }

    fn set_core(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: usize,
        idx: usize,
        value: usize,
    ) -> Result<(), CapaError> {
        let mut ctx = Self::get_context(*domain, core);
        //TODO: we need to unify this with the permission bits.
        //For the moment just allow everything that's within the RiscvField
        //and ignore the rest.
        if !RiscVField::is_valid(idx) {
            log::debug!("Attempt to set invalid field: {:x}", idx);
            return Ok(());
        }
        let field = RiscVField::from_usize(idx).unwrap();
        field.set(&mut ctx, value);
        Ok(())
    }

    fn get_core(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: usize,
        idx: usize,
    ) -> Result<usize, CapaError> {
        let ctx = Self::get_context(*domain, core);
        //TODO: same as above, unify the implementation with permissions.
        if !RiscVField::is_valid(idx) {
            log::debug!("Attempt to get an invalid register {:x}", idx);
            return Ok((0));
        }
        let field = RiscVField::from_usize(idx).unwrap();
        Ok((field.get(&ctx)))
    }

    fn get_core_gp(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: usize,
        result: &mut [usize],
    ) -> Result<(), CapaError> {
        todo!();
    }

    fn dump_in_gp(
        &mut self,
        _engine: &mut MutexGuard<CapaEngine>,
        domain: &mut Handle<Domain>,
        core: usize,
        src: &[usize],
    ) -> Result<(), CapaError> {
        todo!();
    }

    fn extract_from_gp(
        &mut self,
        _engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: usize,
        res: &mut [(usize, usize); 6],
    ) -> Result<(), CapaError> {
        // On riscv, we only use this function for one field at a time.
        // So we have (a3, a4).
        let mut ctx = Self::get_context(*domain, core);
        res[0] = (ctx.reg_state.a3, ctx.reg_state.a4);
        // Say stop.
        res[1] = (!(0 as usize), !(0 as usize));
        Ok(())
    }

    fn check_overlaps(
        &mut self,
        _engine: &mut MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        alias: usize,
        repeat: usize,
        region: &AccessRights,
    ) -> bool {
        // No overlaps on riscv?
        false
    }

    fn map_region(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        alias: usize,
        repeat: usize,
        region: &AccessRights,
    ) -> Result<(), CapaError> {
        //TODO(aghosn): Apparently nothing to do.
        Ok(())
    }

    fn unmap_region(
        &mut self,
        _engine: &mut MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        alias: usize,
        size: usize,
    ) -> Result<(), CapaError> {
        todo!();
    }

    fn prepare_notify(domain: &Handle<Domain>, core_count: usize) {
        if core_count > 0 {
            MONITOR_IPI_SYNC[cpuid()].fetch_add(core_count - 1, Ordering::SeqCst);
        }
    }

    fn notify_cores(_domain: &Handle<Domain>, core_id: usize, core_map: usize) {
        let src_hartid = cpuid();
        for hart in BitmapIterator::new(core_map as u64) {
            if hart != src_hartid {
                aclint_mswi_send_ipi(hart);
            }
        }
    }

    fn acknowledge_notify(domain: &Handle<Domain>) {
        //TODO(aghosn): nothing to do.
    }

    fn finish_notify(domain: &Handle<Domain>) {
        let src_hartid = cpuid();
        while MONITOR_IPI_SYNC[src_hartid].load(Ordering::SeqCst) > 0 {
            core::hint::spin_loop();
        }
    }

    fn context_interrupted(&mut self, domain: &Handle<Domain>, core: usize) {
        todo!();
    }
}

// ————————————————————————— Monitor Implementation ————————————————————————— //

pub struct MonitorRiscv {}

impl Monitor<StateRiscv> for MonitorRiscv {}

impl MonitorRiscv {
    pub fn init() {
        let mut engine = CAPA_ENGINE.lock();
        let domain = engine
            .create_manager_domain(permission::monitor_inter_perm::ALL)
            .unwrap();
        {
            let mut state = StateRiscv {};
            MonitorRiscv::apply_updates(&mut state, &mut engine);
        }
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

        {
            let mut state = StateRiscv {};
            MonitorRiscv::apply_updates(&mut state, &mut engine);
        }

        // Save the initial domain
        let mut initial_domain = INITIAL_DOMAIN.lock();
        *initial_domain = Some(domain);
    }

    pub fn get_active_dom(hartid: usize) -> (Option<Handle<Domain>>) {
        return *ACTIVE_DOMAIN[hartid].lock();
    }

    pub fn set_active_dom(hartid: usize, domain: Handle<Domain>) {
        let mut active_domain = ACTIVE_DOMAIN[hartid].lock();
        *active_domain = Some(domain);
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

        let domain = StateRiscv::get_domain(initial_domain);
        if !domain.data_init_done {
            //update PMP permissions.
            log::debug!("Updating permissions for initial domain.");
            StateRiscv::update_permission(initial_domain, &mut engine);
        }
        StateRiscv::update_pmps(domain);

        (initial_domain)
    }

    // In RISC-V, any trap to machine mode will lead to this function being called (via the machine_trap_handler)
    pub fn handle_exit(reg_state: &mut RegisterState) {
        let mut ret: isize = 0;
        let mut err: usize = 0;
        let mut out_val: usize = 0;
        let mut mcause: usize;
        let mut mepc: usize;
        let mut mstatus: usize;
        let mut mtval: usize;
        let mut sp: usize = 0;
        let mut mie: usize = 0;
        let mut mip: usize = 0;
        let mut mideleg: usize = 0;
        let mut satp: usize = 0;
        let hartid: usize = cpuid();

        unsafe {
            asm!("csrr {}, mcause", out(reg) mcause);
            asm!("csrr {}, mepc", out(reg) mepc);
            asm!("csrr {}, mstatus", out(reg) mstatus);
            asm!("csrr {}, mtval", out(reg) mtval);
            asm!("csrr {}, mie", out(reg) mie);
            asm!("csrr {}, mideleg", out(reg) mideleg);
            asm!("csrr {}, mip", out(reg) mip);
            asm!("csrr {}, satp", out(reg)satp);
        }

        log::trace!("###### TRAP FROM HART {} ######", hartid);

        log::trace!(
        "mcause {:x}, mepc {:x} mstatus {:x} mtval {:x} mie {:x} mip {:x} mideleg {:x} ra {:x} a0 {:x} a1 {:x} a2 {:x} a3 {:x} a4 {:x} a5 {:x} a6 {:x} a7 {:x} satp: {:x}",
        mcause,
        mepc,
        mstatus,
        mtval,
        mie,
        mip,
        mideleg,
        reg_state.ra,
        reg_state.a0,
        reg_state.a1,
        reg_state.a2,
        reg_state.a3,
        reg_state.a4,
        reg_state.a5,
        reg_state.a6,
        reg_state.a7,
        satp
    );

        //TODO(aghosn): dump the reg_state inside the current domain?
        if let Some(active_dom) = Self::get_active_dom(hartid) {
            StateRiscv::save_current_regs(&active_dom, hartid, reg_state);
        }

        // Check which trap it is
        // mcause register holds the cause of the machine mode trap
        match mcause {
            mcause::MSWI => {
                process_ipi(hartid);
                let active_dom = Self::get_active_dom(hartid);
                match active_dom {
                    Some(mut domain) => {
                        let mut state = StateRiscv {};
                        MonitorRiscv::apply_core_updates(&mut state, &mut domain, hartid);
                    }
                    None => {}
                }
            }
            mcause::MTI => {
                clear_mie_mtie();
                log::info!(
                    "\nHART {} MTIMER: MEPC: {:x} RA: {:x}\n",
                    hartid,
                    mepc,
                    reg_state.ra
                );
                aclint_mtimer_set_mtimecmp(hartid, TIMER_EVENT_TICK);
            }
            mcause::MEI => {
                panic!("MEI");
            }
            mcause::ILLEGAL_INSTRUCTION => {
                illegal_instruction_handler(mepc, mtval, mstatus, mip, mie);
            }
            mcause::ECALL_FROM_SMODE => {
                if reg_state.a7 == 0x5479636865 {
                    //Tyche call
                    if reg_state.a0 == 0x5479636865 {
                        log::trace!("Tyche is clearing SIP.SEIE");
                        clear_mip_seip();
                    } else if reg_state.a7 == 0x5479636865 {
                        //TODO(aghosn): commented this.
                        //misaligned_load_handler(/*reg_state*/);
                        Self::wrapper_monitor_call();
                    }
                } else {
                    ecall_handler(&mut ret, &mut err, &mut out_val, *reg_state);
                    reg_state.a0 = ret;
                    reg_state.a1 = out_val as isize;
                }
            }
            mcause::LOAD_ADDRESS_MISALIGNED => {
                panic!("Load address misaligned.");
            }
            mcause::STORE_ACCESS_FAULT
            | mcause::LOAD_ACCESS_FAULT
            | mcause::INSTRUCTION_ACCESS_FAULT => {
                panic!(
                "PMP Access Fault! mcause: {:x} mepc: {:x} mtval: {:x} satp: {:x} mstatus: {:x}",
                mcause, mepc, mtval, satp, mstatus
            );
            }
            mcause::INSTRUCTION_PAGE_FAULT | mcause::LOAD_PAGE_FAULT | mcause::STORE_PAGE_FAULT => {
                panic!(
                    "Page Fault! mcause: {:x} mepc: {:x} mtval: {:x}",
                    mcause, mepc, mtval
                );
            }
            _ => exit_handler_failed(mcause),
            //Default - just print whatever information you can about the trap.
        }

        log::trace!("Returning from Trap on Hart {}", hartid);
        // Return to the next instruction after the trap.
        // i.e. mepc += 4
        // TODO: This shouldn't happen in case of switch.
        if (mcause & (1 << 63)) != (1 << 63) {
            unsafe {
                asm!("csrr t0, mepc");
                asm!("addi t0, t0, 0x4");
                asm!("csrw mepc, t0");
            }
        }
        // Load the state from the current domain.
        if let Some(active_domain) = Self::get_active_dom(hartid) {
            StateRiscv::load_current_regs(&active_domain, hartid, reg_state);
        }
    }

    pub fn wrapper_monitor_call() {
        let mut active_dom: Handle<Domain>;
        let hartid = cpuid();
        active_dom = Self::get_active_dom(hartid).unwrap();
        let (tyche_call, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6) = {
            let ctx = &mut StateRiscv::get_context(active_dom, hartid);
            let tyche_call: usize = ctx.reg_state.a0.try_into().unwrap();
            let arg_1: usize = ctx.reg_state.a1.try_into().unwrap();
            let arg_2: usize = ctx.reg_state.a2;
            let arg_3: usize = ctx.reg_state.a3;
            let arg_4: usize = ctx.reg_state.a4;
            let arg_5: usize = ctx.reg_state.a5;
            let arg_6: usize = ctx.reg_state.a6;
            (tyche_call, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6)
        };
        let mut state = StateRiscv {};
        let args: [usize; 6] = [arg_1, arg_2, arg_3, arg_4, arg_5, arg_6];
        let mut res: [usize; 6] = [0; 6];
        // TODO match the result
        let success =
            Self::do_monitor_call(&mut state, &mut active_dom, tyche_call, &args, &mut res);
        let mut ctx = StateRiscv::get_context(active_dom, hartid);
        match success {
            Ok(true) => {
                ctx.reg_state.a0 = 0;
                ctx.reg_state.a1 = res[0] as isize;
                ctx.reg_state.a2 = res[1];
                ctx.reg_state.a3 = res[2];
                ctx.reg_state.a4 = res[3];
                ctx.reg_state.a5 = res[4];
                ctx.reg_state.a6 = res[5];
            }
            Ok(false) => { /*Nothing to do*/ }
            Err(e) => {
                panic!("Error in vmcall {:?}", e);
            }
        }
        drop(ctx);
        Self::apply_core_updates(&mut state, &mut active_dom, hartid);
        // TODO(aghosn): I commented that out because what about switch?
        // set_active_dom(hartid active_dom);
    }
}
