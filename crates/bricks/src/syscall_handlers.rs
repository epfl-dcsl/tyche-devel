use core::arch::asm;

use crate::bricks_const::{FAILURE, SUCCESS};
use crate::syscalls;
// ———————————————————————————————— Save/restore syscalls ————————————————————————————————— //
use crate::syscalls::LSTAR;
static mut msr_val: u64 = 0;
pub fn save_syscalls() {
    let msr_lstar = x86_64::registers::model_specific::Msr::new(LSTAR as u32);
    unsafe {
        msr_val = msr_lstar.read();
    }
}

pub fn syscalls_init() {
    let mut msr_lstar = x86_64::registers::model_specific::Msr::new(LSTAR as u32);
    let handler_addr = bricks_syscall_handler as u64;
    unsafe {
        msr_lstar.write(handler_addr);
    }
}

pub fn restore_syscalls() {
    let mut msr_lstar = x86_64::registers::model_specific::Msr::new(LSTAR as u32);
    unsafe {
        msr_lstar.write(msr_val);
    }
}

// ———————————————————————————————— Main syscall handler ————————————————————————————————— //

#[no_mangle]
pub extern "C" fn bricks_syscall_handler() {
    let mut rax: usize;
    let rcx: usize;
    let r11: usize;
    let rdi: usize;
    let rsi: usize;
    let rdx: usize;
    unsafe {
        asm!("mov {}, rax", out(reg) rax);
        asm!("mov {}, rcx", out(reg) rcx);
        asm!("mov {}, r11", out(reg) r11);
        asm!("mov {}, rdi", out(reg) rdi);
        asm!("mov {}, rsi", out(reg) rsi);
        asm!("mov {}, rdx", out(reg) rdx);
    }
    let mut result: u32 = FAILURE;
    match rax {
        syscalls::ATTEST_ENCLAVE => {
            result = bricks_attest_enclave_handler(rcx as u32);
        }
        syscalls::PRINT => {
            result = bricks_print_handler();
        }
        syscalls::GATE_CALL => {
            result = bricks_gate_call_handler();
        }
        syscalls::LINUX_MMAP => {
            // TODO implement it
        }
        _ => {
            // TODO implement it
            unsafe {
                asm!("hlt");
            }
        }
    }
    // TODO return result to user code
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
    bricks_gate_call()
}

// TODO
pub fn bricks_print_handler() -> u32 {
    SUCCESS
}
