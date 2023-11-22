#![no_std]
#![no_main]

use core::panic::PanicInfo;

use log::LevelFilter;
use stage_two_abi::entry_point;
use tyche;
use tyche::debug::qemu;
use tyche::{arch, println};

entry_point!(tyche_entry_point);

const LOG_LEVEL: LevelFilter = LevelFilter::Debug;

#[cfg(target_arch = "x86_64")]
fn tyche_entry_point() -> ! {
    arch::arch_entry_point(LOG_LEVEL);
}

#[cfg(target_arch = "riscv64")]
fn tyche_entry_point(hartid: u64, arg1: u64, next_addr: u64, next_mode: u64) -> ! {
    logger::init(LOG_LEVEL);
    arch::arch_entry_point(hartid, arg1, next_addr, next_mode, LOG_LEVEL);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("CPU {}: Panicked", arch::cpuid());
    println!("{:#?}", info);
    qemu::exit(qemu::ExitCode::Failure);
}
