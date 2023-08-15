#![feature(lang_items)]
#![no_std]
#![no_main]

use core::panic::PanicInfo;

pub mod gate_calls;
pub mod interrupts;
pub mod interrupts_handlers;
pub mod shared_buffer;
pub mod syscall_handlers;
pub mod syscalls;

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
