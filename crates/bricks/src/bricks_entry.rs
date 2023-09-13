use core::ffi::c_void;

use crate::arch::{bricks_interrupt_setup, bricks_syscals_setup};
use crate::bricks_testing::bricks_testing;
use crate::bricks_tychools_data::get_tychools_info;
use crate::gate_calls::exit_gate;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct BricksFrame {
    pub handle: u64,
    pub args: *const c_void,
}

pub static mut CURRENT_FRAME: Option<BricksFrame> = None;

#[no_mangle]
pub extern "C" fn bricks_trusted_main(capa_index: u64, args: *const c_void) {
    let br_frame = BricksFrame {
        handle: capa_index,
        args: args,
    };
    let br_frame_curr = br_frame;
    unsafe {
        CURRENT_FRAME = Some(br_frame_curr);
    }
    get_tychools_info();
    interrupt_setup();
    syscall_setup();
    // transition_into_user_mode();
    bricks_testing();
    exit_gate();
}

pub fn interrupt_setup() {
    bricks_interrupt_setup();
}

pub fn syscall_setup() {
    bricks_syscals_setup();
}
