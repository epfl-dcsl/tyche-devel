#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::arch::asm;
use riscv_tyche::{TYCHE_STACK_POINTER};

use log::LevelFilter;
#[cfg(target_arch = "riscv64")]
use riscv_tyche::RVManifest;
use stage_two_abi::entry_point;
use tyche;
use tyche::debug::qemu;
use tyche::{arch, println};

//use core::arch::asm;

entry_point!(tyche_entry_point);

const LOG_LEVEL: LevelFilter = LevelFilter::Info;

#[cfg(target_arch = "x86_64")]
fn tyche_entry_point() -> ! {
    arch::arch_entry_point(LOG_LEVEL);
}

#[cfg(target_arch = "riscv64")]
fn tyche_entry_point(hartid: usize, manifest: RVManifest) -> ! {
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
        asm!(
            "csrr t0, mhartid",
            "slli t0, t0, 3",   // to index into STACK_ADDRESS
            "la t1, {stack}",
            "add t1, t1, t0",
            "ld t1, 0(t1)",
            "mv sp, t1",
            "csrw mscratch, sp",
            stack = sym TYCHE_STACK_POINTER,
        )
    }

    arch::arch_entry_point(hartid, manifest, LOG_LEVEL);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("CPU {}: Panicked", arch::cpuid());
    println!("{:?}", info);
    qemu::exit(qemu::ExitCode::Failure);
}
