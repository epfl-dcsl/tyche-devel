// use core::arch::global_asm;

// global_asm!(include_str!("asm.S"));

use core::arch::asm;
use core::ffi::c_void;

use crate::bricks_entry::interrupt_setup;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct BricksFrame {
    pub handle: u64,
    pub args: *const c_void,
}

const SUCCESS: u32 = 0;
const FAILURE: u32 = 1;
pub static mut current_frame: Option<BricksFrame> = None;

extern "C" {
    fn asm_call_gate(capa_handle: &u64, args: &*const c_void) -> u32;
    fn trusted_entry(frame: &mut BricksFrame);
}

#[no_mangle]
pub extern "C" fn bricks_gate_call() -> u32 {
    let mut result: u32 = FAILURE;
    unsafe {
        if let Some(frame_curr) = &current_frame {
            result = asm_call_gate(&(frame_curr.handle), &(frame_curr.args));
        } else {
            // TODO error
            asm!("hlt");
        }
    }
    result
}

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
    bricks_trusted_entry(&mut br_frame);
}

#[no_mangle]
pub extern "C" fn bricks_trusted_entry(frame: &mut BricksFrame) {
    unsafe {
        trusted_entry(frame);
    }
    bricks_gate_call();
}
