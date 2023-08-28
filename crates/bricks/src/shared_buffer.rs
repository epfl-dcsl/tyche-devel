use core::ffi::{c_char, c_void};

use crate::bricks_const::RET_CODE_BYTES;
use crate::gate_calls::bricks_gate_call;

// This is introduces by tychools
pub const BRICKS_SHARED_BUFFER: usize = 0x300000;

pub const DEBUG_TEST: u64 = 1144;

#[no_mangle]
pub extern "C" fn bricks_get_default_shared_buffer() -> *const c_void {
    BRICKS_SHARED_BUFFER as *const c_void
}

pub fn bricks_get_shared_pointer(offset: u64) -> *mut c_char {
    ((bricks_get_default_shared_buffer() as u64) + offset) as *mut c_char
}

pub fn bricks_write_ret_code(ret_code: u64) {
    let shared = bricks_get_default_shared_buffer() as *mut u64;
    unsafe {
        *shared = ret_code;
    }
}

pub fn bricks_debug(x: u64) {
    bricks_write_ret_code(DEBUG_TEST);
    let sh = bricks_get_shared_pointer(RET_CODE_BYTES) as *mut u64;
    unsafe {
        *sh = x;
    }
    bricks_gate_call();
}
