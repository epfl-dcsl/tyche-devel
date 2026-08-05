#![no_std]
#![no_main]
#![feature(naked_functions)]

use core::panic::PanicInfo;

use log::LevelFilter;
#[cfg(target_arch = "riscv64")]
use riscv_tyche::{RVManifest, TYCHE_STACK_POINTER};
use stage_two_abi::entry_point;
use tyche;
use tyche::debug::qemu;
use tyche::{arch, println};

use core::arch::asm;

entry_point!(tyche_entry_point);

#[cfg(target_arch = "x86_64")]
fn tyche_entry_point() -> ! {
    arch::arch_entry_point(LOG_LEVEL);
}

#[naked]
#[cfg(target_arch = "riscv64")]
extern "C" fn tyche_entry_point(hartid: usize, manifest: RVManifest) -> ! {
    // If logging on VF2 board doesn't work ^ ^ try the following as a debugging starter pack.
    // Loaded in t0 is the serial port base address.
    /* unsafe {
        asm!(
            "li t0, 0x10000000",
            "li t1, 0x41",
            "sb t1, 0(t0)",
            "li t1, 0x42",
            "sb t1, 0(t0)",
            "li t1, 0x43",
            "sb t1, 0(t0)",
        );
    } */

    unsafe {
        // Set up Stack ! 
        asm!(
            "csrr t0, mhartid",
            "slli t0, t0, 3",   // to index into STACK_ADDRESS
            "la t1, {stack}",
            "add t1, t1, t0",
            "ld t1, 0(t1)",
            "mv sp, t1",
            "addi sp, sp, -9*8",
            // "mv a0, {hartid}",   Should already remain ... 
            // "mv a1, {manifest}",
            "j {arch_entry}",
            stack = sym TYCHE_STACK_POINTER, 
            arch_entry = sym arch::arch_entry_point,
            options(noreturn),
        );
    }

}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("CPU {}: Panicked", arch::cpuid());
    println!("{:?}", info);
    qemu::exit(qemu::ExitCode::Failure);
}
