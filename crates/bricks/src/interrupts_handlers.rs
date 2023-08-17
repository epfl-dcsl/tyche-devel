use core::arch::asm;

use crate::gate_calls::bricks_gate_call;
use crate::shared_buffer::bricks_get_default_shared_buffer;

const EXCEPTION_CONST: u64 = 888;
const DIVIDE_ZERO_CONST: u64 = 999;

#[no_mangle]
pub extern "C" fn bricks_exception_handler() {
    let shared_buff_u64 = bricks_get_default_shared_buffer() as *mut u64;
    unsafe {
        *shared_buff_u64 = EXCEPTION_CONST;
    }
    bricks_gate_call();
}

#[no_mangle]
pub extern "C" fn bricks_divide_zero_handler() {
    let shared_buff_u64 = bricks_get_default_shared_buffer() as *mut u64;
    unsafe {
        *shared_buff_u64 = DIVIDE_ZERO_CONST;
    }
    bricks_gate_call();
}

// ———————————————————————————————— Handlers for x86_64 crate ————————————————————————————————— //

use x86_64::structures::idt::InterruptStackFrame;

pub extern "x86-interrupt" fn bricks_x86_64_handler(stack_frame: InterruptStackFrame) {}

pub extern "x86-interrupt" fn bricks_x86_64_handler_double(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    panic!("Panicking: double fault")
}

pub extern "x86-interrupt" fn bricks_divide_zero_handler_x86(stack_frame: InterruptStackFrame) {
    bricks_divide_zero_handler();
}
