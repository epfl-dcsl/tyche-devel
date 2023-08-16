use core::arch::asm;

use crate::gate_calls::bricks_gate_call;
use crate::shared_buffer::bricks_get_default_shared_buffer;

const EXCEPTION_CONST: u64 = 777;
const DIVIDE_ZERO_CONST: u64 = 666;

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
