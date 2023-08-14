use core::arch::asm;

use crate::syscalls;

#[no_mangle]
pub extern "C" fn syscall_handler() {
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

    match rax {
        syscalls::ATTEST_ENCLAVE => {
            // TODO implement it
        }
        syscalls::LINUX_MALLOC => {
            // TODO implement it
        }
        _ => {
            // TODO implement it
        }
    }
}
