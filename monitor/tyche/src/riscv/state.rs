use core::arch::asm;
use core::sync::atomic::AtomicUsize;

use capa_engine::config::{NB_CORES, NB_DOMAINS, NB_REMAP_REGIONS};
use capa_engine::{CapaEngine, Domain, Handle, MemOps};
use riscv_pmp::csrs::{pmpaddr_csr_write, pmpcfg_csr_write};
use riscv_pmp::{
    clear_pmp, pmp_write_compute, PMPAddressingMode, PMPWriteResponse, FROZEN_PMP_ENTRIES,
    PMP_CFG_ENTRIES, PMP_ENTRIES,
};
use riscv_utils::{
    read_medeleg, read_mepc, read_mscratch, read_satp, toggle_supervisor_interrupts, write_medeleg,
    write_mepc, write_mscratch, write_satp, RegisterState, NUM_HARTS,
};
use spin::{Mutex, MutexGuard};

use crate::monitor::{PlatformState, CAPA_ENGINE};
use crate::riscv::context::ContextRiscv;
// ———————————————————————————————— Globals ————————————————————————————————— //

pub static DOMAINS: [Mutex<DataRiscv>; NB_DOMAINS] = [EMPTY_DOMAIN; NB_DOMAINS];
pub static CONTEXTS: [[Mutex<ContextRiscv>; NB_CORES]; NB_DOMAINS] =
    [EMPTY_CONTEXT_ARRAY; NB_DOMAINS];
pub static MONITOR_IPI_SYNC: [AtomicUsize; NUM_HARTS] = [ZERO; NUM_HARTS];

// —————————————————————————————— Empty Values —————————————————————————————— //

const EMPTY_DOMAIN: Mutex<DataRiscv> = Mutex::new(DataRiscv {
    data_init_done: false,
    pmpaddr: [0; PMP_ENTRIES],
    pmpcfg: [0; PMP_CFG_ENTRIES],
});

const EMPTY_CONTEXT: Mutex<ContextRiscv> = Mutex::new(ContextRiscv {
    reg_state: RegisterState::const_default(),
    satp: 0,
    mepc: 0,
    sp: 0,
    medeleg: 0,
});

const EMPTY_CONTEXT_ARRAY: [Mutex<ContextRiscv>; NB_CORES] = [EMPTY_CONTEXT; NB_CORES];

pub const ZERO: AtomicUsize = AtomicUsize::new(0);
// ————————————————————————————— Implementation ————————————————————————————— //

pub struct DataRiscv {
    pub data_init_done: bool,
    pub pmpaddr: [usize; PMP_ENTRIES],
    pub pmpcfg: [usize; PMP_CFG_ENTRIES],
}

pub struct StateRiscv {}

impl StateRiscv {
    pub fn save_current_regs(
        current_domain: &Handle<Domain>,
        hart: usize,
        reg_state: &RegisterState,
    ) {
        let dom_ctx = &mut Self::get_context(*current_domain, hart);
        dom_ctx.reg_state = *reg_state;
    }

    pub fn load_current_regs(
        current_domain: &Handle<Domain>,
        hart: usize,
        reg_state: &mut RegisterState,
    ) {
        let dom_ctx = Self::get_context(*current_domain, hart);
        *reg_state = dom_ctx.reg_state;
    }

    pub fn update_pmps(domain: MutexGuard<DataRiscv>) {
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

    pub fn switch_domain(
        current_domain: &mut Handle<Domain>,
        current_ctx: &mut MutexGuard<ContextRiscv>,
        next_ctx: &mut MutexGuard<ContextRiscv>,
        next_domain: MutexGuard<DataRiscv>,
        domain: Handle<Domain>,
    ) {
        log::debug!(
            "writing satp: {:x} mepc {:x} mscratch: {:x}",
            next_ctx.satp,
            next_ctx.mepc,
            next_ctx.sp
        );
        //Save current context
        //TODO: do this before.
        //current_ctx.reg_state = *current_reg_state;
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
        //TODO: change the architecture to read the context.
        //*current_reg_state = next_ctx.reg_state;

        //IMP TODO: Toggling interrupts based on the assumption that we are running initial domain and
        //one more domain - This needs to be implemented for more generic cases via per core updates.
        toggle_supervisor_interrupts();

        if (next_domain.data_init_done) {
            Self::update_pmps(next_domain);
        } else {
            panic!("THIS SHOULD NEVER HAPPEN!");
            let mut engine = CAPA_ENGINE.lock();
            Self::update_permission(domain, &mut engine);
        }
    }

    pub fn update_domain_pmp(
        domain_handle: Handle<Domain>,
        pmp_index: usize,
        pmp_addr: usize,
        pmp_cfg: usize,
    ) {
        let mut domain = StateRiscv::get_domain(domain_handle);
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
}
