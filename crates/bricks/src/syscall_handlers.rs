use syscalls::*;

#[no_mangle]
pub extern "C" fn syscall_handler() {
    let rax : u64;
    let rcx : u64;
    let r11 : u64;
    let rdi : u64;
    let rsi : u64;
    let rdx : u64;
    unsafe {
        asm!("mov {:e}, rax", out(reg) rax);
        asm!("mov {:e}, rcx", out(reg) rcx);
        asm!("mov {:e}, r11", out(reg) r11);
        asm!("mov {:e}, rdi", out(reg) rdi);
        asm!("mov {:e}, rsi", out(reg) rsi);
        asm!("mov {:e}, rdx", out(reg) rdx);
    }

    match rax {
        ENCLAVE_ATTESTATION => {
            // TODO implement it
        }
        LINUX_MALLOC => {
            // TODO implement it
        }
        _ => {
            // TODO implement it
        }
    }
}