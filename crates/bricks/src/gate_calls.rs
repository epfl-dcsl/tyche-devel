use core::ffi::c_void;

use crate::arch;
use crate::bricks_const::FAILURE;
use crate::bricks_entry::current_frame;
use crate::shared_buffer::bricks_write_ret_code;

extern "C" {
    fn asm_call_gate(capa_handle: &u64, args: &*const c_void) -> u64;
}

// Gate call to return to untrusted part
pub fn bricks_gate_call() -> u64 {
    let mut result: u64 = FAILURE;
    unsafe {
        if let Some(frame_curr) = &current_frame {
            result = asm_call_gate(&(frame_curr.handle), &(frame_curr.args));
        } else {
            arch::halt();
        }
    }
    result
}

// Exits enclave with exit code
const EXIT_GATE: u64 = 107;
pub fn exit_gate() {
    bricks_write_ret_code(EXIT_GATE);
    bricks_gate_call();
}
