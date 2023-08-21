use core::ffi::{c_char, c_void};

// This is introduces by tychools
pub const BRICKS_SHARED_BUFFER: usize = 0x300000;

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
