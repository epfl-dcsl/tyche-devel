use core::arch::asm;
use core::ffi::c_char;

use crate::bricks_const::{FAILURE, RET_CODE_BYTES, SUCCESS};
use crate::bricks_utils::{bricks_memcpy, bricks_strlen};
use crate::profiles::check_syscalls_kill;
use crate::shared_buffer::{bricks_get_shared_pointer, bricks_write_ret_code};
use crate::syscalls;
// ———————————————————————————————— Main syscall handler ————————————————————————————————— //
#[no_mangle]
pub extern "C" fn bricks_syscall_handler() {
    if check_syscalls_kill() {
        exit_gate();
    }
    // Guard to make sure cpu halts if someone calls syscall - for now
    x86_64::instructions::hlt();
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
            result = bricks_print_handler(rdi as *mut c_char);
        }
        syscalls::GATE_CALL => {
            result = bricks_gate_call_handler();
        }
        syscalls::WRITE_SHARED => {
            result = bricks_write_shared_handler(rdi as *mut c_char, rsi as u32);
        }
        syscalls::READ_SHARED => {
            result = bricks_read_shared_handler(rdi as *mut c_char, rsi as u32);
        }
        syscalls::MALLOC => {
            let pointer = bricks_malloc_handler(rdi as usize);
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

// ———————————————————————————————— Helping handlers (logic for handlers) ————————————————————————————————— //

// TODO add pointer to the structure where to write result
#[no_mangle]
pub extern "C" fn bricks_attest_enclave_handler(nonce: u32) -> u32 {
    enclave_attestation_tyche(nonce)
}

use crate::gate_calls::{bricks_gate_call, exit_gate};
use crate::tyche_api::enclave_attestation_tyche;
#[no_mangle]
pub extern "C" fn bricks_gate_call_handler() -> u32 {
    bricks_write_ret_code(syscalls::GATE_CALL as u64);
    bricks_gate_call()
}

#[no_mangle]
pub extern "C" fn bricks_print_handler(buff: *mut c_char) -> u32 {
    bricks_write_ret_code(syscalls::PRINT as u64);
    let shared_buff_str = bricks_get_shared_pointer(RET_CODE_BYTES);
    let cnt_chars = bricks_strlen(buff);
    bricks_memcpy(shared_buff_str, buff, cnt_chars);
    bricks_gate_call();
    SUCCESS
}

#[no_mangle]
pub extern "C" fn bricks_write_shared_handler(buff: *mut c_char, cnt: u32) -> u32 {
    bricks_write_ret_code(syscalls::WRITE_SHARED as u64);
    let shared_buff_str = bricks_get_shared_pointer(RET_CODE_BYTES);
    bricks_memcpy(shared_buff_str, buff, cnt);
    bricks_gate_call();
    SUCCESS
}

#[no_mangle]
pub extern "C" fn bricks_read_shared_handler(buff: *mut c_char, cnt: u32) -> u32 {
    let shared_buff_str = bricks_get_shared_pointer(RET_CODE_BYTES);
    bricks_memcpy(shared_buff_str, buff, cnt);
    SUCCESS
}

#[no_mangle]
pub extern "C" fn bricks_malloc_handler(num_bytes: usize) -> *mut i8 {
    let (cr3, _) = x86_64::registers::control::Cr3::read();
    bricks_write_ret_code(1144);
    let x = cr3.start_address().as_u64();
    let pt = bricks_get_shared_pointer(8) as *mut u64;
    unsafe {
        *pt = x;
    }
    bricks_gate_call();
    unsafe {
        asm!("hlt");
    }
    return core::ptr::null_mut() as *mut i8;
}

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
