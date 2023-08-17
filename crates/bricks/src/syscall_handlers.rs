use core::arch::asm;

use crate::bricks_const::{FAILURE, SUCCESS};
use crate::syscalls;

#[no_mangle]
pub extern "C" fn bricks_syscall_handler() {
    let mut rax: usize;
    let rcx: usize;
    let r11: usize;
    let rdi: usize;
    let rsi: usize;
    let rdx: usize;
    unsafe {
        asm!("mov {:}, rax", out(reg) rax);
        asm!("mov {:}, rcx", out(reg) rcx);
        asm!("mov {:}, r11", out(reg) r11);
        asm!("mov {:}, rdi", out(reg) rdi);
        asm!("mov {:}, rsi", out(reg) rsi);
        asm!("mov {:}, rdx", out(reg) rdx);
    }
    let mut result: u32 = FAILURE;
    match rax {
        syscalls::ATTEST_ENCLAVE => {
            result = bricks_attest_enclave_handler();
        }
        syscalls::PRINT => {
            // TODO implement it
        }
        syscalls::EDGE_CALL => {
            result = bricks_edge_call_handler();
        }
        syscalls::LINUX_MMAP => {
            // TODO implement it
        }
        _ => {
            // TODO implement it
        }
    }
    // TODO return result to user code
}

// TODO
pub fn bricks_attest_enclave_handler() -> u32 {
    SUCCESS
}

use crate::gate_calls::bricks_gate_call;
pub fn bricks_edge_call_handler() -> u32 {
    bricks_gate_call()
}

// TODO
pub fn bricks_print_handler() -> u32 {
    SUCCESS
}
