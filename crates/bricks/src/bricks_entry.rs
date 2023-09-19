use core::ffi::c_void;

use crate::arch::transition::transition_into_user_mode;
use crate::arch::{bricks_interrupt_setup, bricks_syscall_setup};
use crate::bricks_testing::bricks_testing;
use crate::bricks_tychools_data::get_tychools_info;
use crate::bricks_utils::bricks_print;
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
    bricks_interrupt_setup();
    bricks_syscall_setup();
    bricks_print("Transitioning to user mode, good luck...");
    transition_into_user_mode();
    bricks_testing();
    exit_gate();
}
