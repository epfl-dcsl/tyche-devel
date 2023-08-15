// use core::arch::global_asm;

// global_asm!(include_str!("asm.S"));

use core::ffi::c_void;

#[repr(C)]
pub struct BricksFrame {
    pub handle: u64,
    pub args: *const c_void,
}

const SUCCESS: u32 = 0;
const FAILURE: u32 = 1;

extern "C" {
    fn asm_call_gate(capa_handle: &u64, args: &*const c_void) -> u32;
}

#[no_mangle]
pub extern "C" fn bricks_gate_call(frame: &mut BricksFrame) -> u32 {
    let mut result: u32 = FAILURE;
    unsafe {
        result = asm_call_gate(&(frame.handle), &(frame.args));
    }
    result
}

// #[no_mangle]
// pub extern "C" fn asm_call_gate_bricks(capa_handle: &u64, args:&*const c_void) -> u32 {
//     unsafe {
//         asm_call_gate(capa_handle, args)
//     }
// }
