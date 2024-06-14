//! Risc-V backend

// TODO: remove this once the backend is implemented.
// The line just removes the unused warnings.
#![allow(unused)]

mod arch;
mod filtered_fields;
pub mod guest;
mod init;
mod monitor;
mod riscv_tpm_attestation;
use core::arch::asm;

pub use init::arch_entry_point;
use mmu::FrameAllocator;
use riscv_csrs::mstatus;

use crate::debug::qemu::ExitCode;
use crate::println;

// TODO: some empty types to be filled.
#[derive(Debug)]
pub enum BackendError {}

// launch the initial domain.
pub fn launch_guest(hartid: usize, arg1: usize, next_addr: usize, next_mode: usize) {
    // 0. TODO: Sanity check for next_mode and misa-extension.

    log::info!("============= Launching Linux from Tyche =============");

    // 1. Update MSTATUS - MPP=01 (S-mode), and MPIE = 0.
    let mut mstatus: usize;
    let zero: usize = 0;
    unsafe {
        asm!("csrr {}, mstatus", out(reg) mstatus);
    }
    //clear MPP
    mstatus = mstatus & !(mstatus::MPP_MASK << mstatus::MPP_LOW);
    //set MPP = 01 i.e. S-mode
    mstatus |= 1 << mstatus::MPP_LOW;

    //reset mpie
    mstatus = mstatus & !(1 << mstatus::MPIE);

    //write updated mstatus
    unsafe {
        asm!("csrw mstatus, {}", in(reg) mstatus);
    }

    // 2. Update MEPC to next_addr
    //mepc::write(next_addr);
    unsafe {
        asm!("csrw mepc, {}",
         in(reg) next_addr,);
    }

    // 3. Update S-mode registers - stvec = next_addr, sscratch = 0, sie = 0, satp = 0
    //stvec::write(next_addr);
    unsafe {
        asm!("csrw stvec, {}",
         in(reg) next_addr,);
        asm!("csrw sscratch, {}",
         in(reg) zero,);
        asm!("csrw sie, {}",
         in(reg) zero,);
        asm!("csrw satp, {}",
         in(reg) zero,);

        // 4. writing args to a0 and a1
        asm!("mv a0, {}",
         in(reg) hartid,);
        asm!("mv a1, {}",
         in(reg) arg1,);

        // 5. mret
        asm!("mret", options(noreturn));
    }
}

/// Halt the CPU in a spinloop;
pub fn hlt() -> ! {
    loop {
        // See core::arch::asm::riscv64:
        //
        // The PAUSE instruction is a HINT that indicates the current hart's rate of instruction retirement
        // should be temporarily reduced or paused. The duration of its effect must be bounded and may be zero.
        unsafe { asm!(".insn i 0x0F, 0, x0, x0, 0x010", options(nomem, nostack)) }
    }
}

pub fn exit_qemu(exit_code: ExitCode) {
    // TODO: find exit address
    const RISCV_EXIT_ADDR: usize = 0xdeadbeef;

    unsafe {
        let exit_code = exit_code as u32;
        asm!(
            "sw {0}, 0({1})",
            in(reg) exit_code,
            in(reg) RISCV_EXIT_ADDR
        );
    }
}

pub fn cpuid() -> usize {
    let hartid: usize;

    unsafe {
        asm!("csrr {}, mhartid", out(reg) hartid);
    }

    hartid
}
