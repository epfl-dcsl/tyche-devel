use core::arch::asm;
use core::ffi::c_void;

use crate::bricks_const::FAILURE;
use crate::bricks_entry::{interrupt_setup, syscall_setup};
use crate::shared_buffer::bricks_write_ret_code;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct BricksFrame {
    pub handle: u64,
    pub args: *const c_void,
}

pub static mut current_frame: Option<BricksFrame> = None;

extern "C" {
    fn asm_call_gate(capa_handle: &u64, args: &*const c_void) -> u32;
    fn trusted_entry(frame: &mut BricksFrame);
}

// Gate call to return to untrusted part
pub fn bricks_gate_call() -> u32 {
    let mut result: u32 = FAILURE;
    unsafe {
        if let Some(frame_curr) = &current_frame {
            result = asm_call_gate(&(frame_curr.handle), &(frame_curr.args));
        } else {
            asm!("hlt");
        }
    }
    result
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
    interrupt_setup();
    syscall_setup();
    bricks_trusted_entry(&mut br_frame);
}

// Exits enclave with exit code
const EXIT_GATE: u64 = 107;
pub fn exit_gate() {
    bricks_write_ret_code(EXIT_GATE);
    bricks_gate_call();
}

// Called from bricks_trusted_main, wrapper for user entry
#[no_mangle]
pub extern "C" fn bricks_trusted_entry(frame: &mut BricksFrame) {
    unsafe {
        trusted_entry(frame);
    }
    exit_gate();
}
