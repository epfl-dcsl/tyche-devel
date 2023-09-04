use core::arch::asm;
use core::ffi::c_void;

use crate::arch::{bricks_init_transition, bricks_interrupt_setup, bricks_syscals_setup};
use crate::bricks_tychools_data::get_tychools_info;
use crate::gate_calls::exit_gate;
use crate::shared_buffer::bricks_debug;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct BricksFrame {
    pub handle: u64,
    pub args: *const c_void,
}

pub static mut current_frame: Option<BricksFrame> = None;

extern "C" {
    fn trusted_entry();
}

// Called from trusted_main with same args
#[no_mangle]
pub extern "C" fn bricks_trusted_main(capa_index: u64, args: *const c_void) {
    let mut br_frame = BricksFrame {
        handle: capa_index,
        args: args,
    };
    let br_frame_curr = br_frame;
    unsafe {
        current_frame = Some(br_frame_curr);
    }
    get_tychools_info();
    interrupt_setup();
    syscall_setup();
    tranistion_setup();
    // transition_into_user_mode();
    bricks_trusted_entry(&mut br_frame);
}

// Called from bricks_trusted_main, wrapper for user entry
#[no_mangle]
pub extern "C" fn bricks_trusted_entry(frame: &mut BricksFrame) {
    unsafe {
        trusted_entry();
    }
    exit_gate();
}

pub fn interrupt_setup() {
    bricks_interrupt_setup();
}

pub fn syscall_setup() {
    bricks_syscals_setup();
}

pub fn tranistion_setup() {
    bricks_init_transition();
}
