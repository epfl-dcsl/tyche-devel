#![no_std]
#![no_main]

use core::panic::PanicInfo;

use log::LevelFilter;
use stage_two_abi::entry_point;
use tyche;
use tyche::debug::qemu;
use tyche::{arch, println};

entry_point!(tyche_entry_point);

const LOG_LEVEL: LevelFilter = LevelFilter::Info;

#[cfg(target_arch = "x86_64")]
fn tyche_entry_point() -> ! {
    arch::arch_entry_point(LOG_LEVEL);
}

#[cfg(target_arch = "riscv64")]
fn tyche_entry_point(
    hartid: usize,
    arg1: usize,
    next_addr: usize,
    next_mode: usize,
    coldboot: bool,
) -> ! {
    arch::arch_entry_point(hartid, arg1, next_addr, next_mode, coldboot, LOG_LEVEL);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("CPU {}: Panicked", arch::cpuid());
    println!("{:#?}", info);
    qemu::exit(qemu::ExitCode::Failure);
}
