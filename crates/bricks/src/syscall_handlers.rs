use core::arch::asm;
use core::ffi::c_char;

use crate::bricks_const::{FAILURE, SUCCESS};
use crate::shared_buffer::bricks_get_default_shared_buffer;
use crate::syscalls;
// ———————————————————————————————— Save/restore syscalls ————————————————————————————————— //
use crate::syscalls::LSTAR;
static mut msr_val: u64 = 0;
pub fn bricks_save_syscalls() {
    let msr_lstar = x86_64::registers::model_specific::Msr::new(LSTAR as u32);
    unsafe {
        msr_val = msr_lstar.read();
    }
}

pub fn bricks_syscalls_init() {
    let mut msr_lstar = x86_64::registers::model_specific::Msr::new(LSTAR as u32);
    let handler_addr = bricks_syscall_handler as u64;
    unsafe {
        msr_lstar.write(handler_addr);
    }
}

pub fn bricks_restore_syscalls() {
    let mut msr_lstar = x86_64::registers::model_specific::Msr::new(LSTAR as u32);
    unsafe {
        msr_lstar.write(msr_val);
    }
}

// ———————————————————————————————— Main syscall handler ————————————————————————————————— //

const SYSCALL_CONST : u64 = 1111;
#[no_mangle]
pub extern "C" fn bricks_syscall_handler() {
    let shared_buff_u64 = bricks_get_default_shared_buffer() as *mut u64;
    unsafe {
        *shared_buff_u64 = SYSCALL_CONST;
    }
    bricks_gate_call();
    // Guard to make sure cpu halts if someone calls syscall
    unsafe {
        asm!("hlt");
    }
    let mut rax: usize;
    let r10: usize;
    let rdi: usize;
    let rsi: usize;
    let rdx: usize;
    unsafe {
        asm!("mov {}, rax", out(reg) rax);
        asm!("mov {}, rdi", out(reg) rdi);
        asm!("mov {}, rsi", out(reg) rsi);
        asm!("mov {}, rdx", out(reg) rdx);
        asm!("mov {}, r10", out(reg) r10);
    }
    let result: u32;
    match rax {
        syscalls::ATTEST_ENCLAVE => {
            result = bricks_attest_enclave_handler(rdi as u32);
        }
        syscalls::PRINT => {
            result = bricks_print_handler(rdi as * mut c_char);
        }
        syscalls::GATE_CALL => {
            result = bricks_gate_call_handler();
        }
        syscalls::LINUX_MMAP => {
            // TODO implement it
        }
        _ => {
            // TODO implement it
            result = FAILURE;
            unsafe {
                asm!("hlt");
            }
        }
    }
    // TODO return from syscall doesn't work
    // unsafe {
    //     asm!("sysret");
    // }
}

// ———————————————————————————————— Helping handlers ————————————————————————————————— //

// TODO
#[no_mangle]
pub extern "C" fn bricks_attest_enclave_handler(nonce: u32) -> u32 {
    enclave_attestation_tyche(nonce)
}

use crate::gate_calls::bricks_gate_call;
use crate::tyche_api::enclave_attestation_tyche;
#[no_mangle]
pub extern "C" fn bricks_gate_call_handler() -> u32 {
    // let shared_buff_u64 = bricks_get_default_shared_buffer() as *mut u64;
    // unsafe {
    //     *shared_buff_u64 = syscalls::GATE_CALL as u64;
    // }
    bricks_gate_call()
}

#[no_mangle]
pub extern "C" fn bricks_print_handler(buff : * mut c_char) -> u32 {
    let shared_buff_u64 = bricks_get_default_shared_buffer() as *mut u64;
    unsafe {
        *shared_buff_u64 = syscalls::PRINT as u64;
    }
    let mut shared_buff_str = ((shared_buff_u64 as u64) + 8) as * mut c_char;
    let mut buff_cpy = buff;
    while true {
        unsafe {
            *shared_buff_str = *buff_cpy;
        }
        unsafe {
            if *buff_cpy == ('\0' as i8) {
                break;
            }
        }
        buff_cpy = ((buff_cpy as u64) + 1) as * mut c_char;
        shared_buff_str = ((shared_buff_str as u64) + 1) as * mut c_char;

    }
    bricks_gate_call();
    SUCCESS
}
