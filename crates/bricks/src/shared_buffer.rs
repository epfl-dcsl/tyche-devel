use core::ffi::c_void;

// This is introduces by tychools
pub const BRICKS_SHARED_BUFFER: usize = 0x300000;

#[no_mangle]
pub extern "C" fn bricks_get_default_shared_buffer() -> *const c_void {
    BRICKS_SHARED_BUFFER as *const c_void
}
