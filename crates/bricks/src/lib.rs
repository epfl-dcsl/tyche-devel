#![feature(lang_items)]
#![feature(abi_x86_interrupt)]
#![feature(stmt_expr_attributes)]
#![no_std]
#![no_main]

use core::panic::PanicInfo;

pub mod allocator;
pub mod bricks_const;
pub mod bricks_entry;
pub mod bricks_utils;
pub mod gate_calls;
pub mod interrupts;
pub mod profiles;
pub mod shared_buffer;
pub mod syscalls;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

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

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    loop {}
}

#[lang = "eh_personality"]
extern "C" fn eh_personality() {}
