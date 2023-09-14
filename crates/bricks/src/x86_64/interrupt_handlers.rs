use core::arch::asm;

use crate::gate_calls::{bricks_gate_call, exit_gate};
use crate::profiles::{check_exceptions_ignore, check_exceptions_kill};
use crate::shared_buffer::bricks_write_ret_code;

const EXCEPTION_CONST: u64 = 111;
const DIVIDE_ZERO_CONST: u64 = 222;

// ———————————————————————————————— Logic for handlers ————————————————————————————————— //
pub fn bricks_exception_handler() {
    bricks_write_ret_code(EXCEPTION_CONST);
    bricks_gate_call();
}

pub fn bricks_divide_zero_handler() {
    bricks_write_ret_code(DIVIDE_ZERO_CONST);
    bricks_gate_call();
}

// ———————————————————————————————— Handlers for x86_64 crate (x86-interrupt) ————————————————————————————————— //

use x86_64::structures::idt::InterruptStackFrame;

pub extern "x86-interrupt" fn bricks_x86_64_handler(_stack_frame: InterruptStackFrame) {
    if check_exceptions_kill() {
        bricks_exception_handler();
    } else if check_exceptions_ignore() {
        unsafe {
            asm!("iretq");
        }
    }
}

pub extern "x86-interrupt" fn bricks_x86_64_handler_double(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    exit_gate();
    panic!("Panicking: double fault")
}

pub extern "x86-interrupt" fn bricks_divide_zero_handler_x86(_stack_frame: InterruptStackFrame) {
    if check_exceptions_kill() {
        bricks_divide_zero_handler();
    } else if check_exceptions_ignore() {
        unsafe {
            asm!("iretq");
        }
    }
}
