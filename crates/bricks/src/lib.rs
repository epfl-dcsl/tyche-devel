#![feature(lang_items)]
#![feature(abi_x86_interrupt)]
#![feature(stmt_expr_attributes)]
#![no_std]
#![no_main]

use core::arch::{asm,global_asm};
use core::panic::PanicInfo;

pub mod allocator;
pub mod bricks_const;
pub mod bricks_entry;
pub mod bricks_tychools_data;
pub mod bricks_utils;
pub mod gate_calls;
pub mod interrupts;
pub mod profiles;
pub mod shared_buffer;
pub mod syscalls;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
global_asm!(include_str!("x86_64/entry.S"), options(att_syntax));

#[cfg(target_arch = "x86_64")]
pub mod arch {
    pub use crate::x86_64::*;
}

#[cfg(target_arch = "riscv64")]
pub mod riscv;

#[no_mangle]
pub extern "C" fn bricks_function(a: u32, b: u32) -> u32 {
    a + b
}

extern "C" {
    fn bricks_start();
}
#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        bricks_start();
    }
    panic!("Panic: shouldn't coem to the end of _start")
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    loop {}
}

#[lang = "eh_personality"]
extern "C" fn eh_personality() {}
