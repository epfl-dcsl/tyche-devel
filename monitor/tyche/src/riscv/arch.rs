//! Architecture specific structures

use core::arch::asm;

use riscv_csrs::*;
use riscv_sbi::*;
use riscv_tyche::*;
use riscv_utils::*;

use crate::println;
use crate::riscv::guest::machine_trap_handler;

#[cfg(not(feature = "visionfive2"))]
pub fn init(hartid: usize) {
    unsafe {
        asm!("csrw mscratch, {}", in(reg) TYCHE_STACK_POINTER[hartid]);
    }

    clear_mstatus_sie();
    set_mstatus_mie();
    // Configuring mtvec direct base address to point to Tyche's trap handler.
    let mtvec_ptr = machine_trap_handler as *const ();
    log::info!("mtvec_ptr to be set by Tyche {:p}", mtvec_ptr);
    set_mtvec(mtvec_ptr);
}

#[cfg(feature = "visionfive2")]
pub fn init() {
    let mut medeleg: usize;
    unsafe {
        asm!("csrw mscratch, {}", in(reg) VF2_TYCHE_STACK_POINTER);
    }

    // Configuring mtvec direct base address to point to Tyche's trap handler.
    let mtvec_ptr = machine_trap_handler as *const ();
    log::info!("mtvec_ptr to be set by Tyche {:p}", mtvec_ptr);
    set_mtvec(mtvec_ptr);
}

// ------------------------------ Trap Handler Setup -------------------------- //

pub fn set_mtvec(addr: *const ()) {
    unsafe {
        asm!("csrw mtvec, {}", in(reg) addr);
    }

    let mut mtvec: usize;
    unsafe {
        asm!("csrr {}, mtvec", out(reg) mtvec);
    }

    log::info!("Updated mtvec {:x}", mtvec);
}
