use core::ffi::{c_char, c_void};

use crate::allocator::{alloc_user, free_user};
use crate::bricks_const::{FAILURE, RET_CODE_BYTES, SUCCESS};
use crate::bricks_structs::AttestationResult;
use crate::bricks_utils::{bricks_memcpy, bricks_strlen};
use crate::gate_calls::{bricks_gate_call, exit_gate};
use crate::profiles::check_syscalls_kill;
use crate::shared_buffer::{bricks_get_shared_pointer, bricks_write_ret_code};
use crate::syscalls;

// ———————————————————————————————— Main syscall handler ————————————————————————————————— //

#[no_mangle]
#[used]
pub static mut USER_RSP: usize = 0;
#[no_mangle]
#[used]
pub static mut SAVE_RAX: usize = 0;
#[no_mangle]
#[used]
pub static mut SAVE_RCX: usize = 0;
#[no_mangle]
#[used]
pub static mut SAVE_RDI: usize = 0;
#[no_mangle]
#[used]
pub static mut SAVE_RSI: usize = 0;
#[no_mangle]
#[used]
pub static mut BRICKS_RSP: usize = 0;
#[no_mangle]
pub extern "C" fn bricks_syscall_handler() {
    let rax: usize;
    let rdi: usize;
    let rsi: usize;
    unsafe {
        rax = SAVE_RAX;
        rdi = SAVE_RDI;
        rsi = SAVE_RSI;
    }
    if check_syscalls_kill() {
        exit_gate();
    }
    let _result: u64;
    match rax {
        syscalls::ATTEST_ENCLAVE => {
            _result = bricks_attest_enclave_handler(rdi as u64, rsi as *mut AttestationResult);
        }
        syscalls::PRINT => {
            _result = bricks_print_handler(rdi as *mut c_char);
        }
        syscalls::WRITE_SHARED => {
            _result = bricks_write_shared_handler(rdi as *mut c_char, rsi as u32);
        }
        syscalls::READ_SHARED => {
            _result = bricks_read_shared_handler(rdi as *mut c_char, rsi as u32);
        }
        syscalls::SBRK => {
            _result = bricks_sbrk_handler(rdi as usize);
        }
        syscalls::BRK => {
            _result = bricks_brk_handler(rdi as *mut c_void);
        }
        syscalls::EXIT => {
            exit_gate();
        }
        _ => {
            _result = FAILURE;
            exit_gate();
        }
    }
}

// ———————————————————————————————— Helping handlers (logic for handlers) ————————————————————————————————— //

pub fn bricks_attest_enclave_handler(nonce: u64, result_struct: *mut AttestationResult) -> u64 {
    let ref_struct: &mut AttestationResult;
    unsafe {
        ref_struct = &mut *result_struct;
    }
    enclave_attestation_tyche(nonce, ref_struct)
}

pub fn bricks_print_handler(buff: *mut c_char) -> u64 {
    bricks_write_ret_code(syscalls::PRINT as u64);
    let shared_buff_str = bricks_get_shared_pointer(RET_CODE_BYTES);
    let cnt_chars = bricks_strlen(buff);
    bricks_memcpy(shared_buff_str, buff, cnt_chars);
    bricks_gate_call();
    SUCCESS
}

pub fn bricks_write_shared_handler(buff: *mut c_char, cnt: u32) -> u64 {
    bricks_write_ret_code(syscalls::WRITE_SHARED as u64);
    let shared_buff_num_bytes = bricks_get_shared_pointer(RET_CODE_BYTES) as *mut u64;
    unsafe {
        *shared_buff_num_bytes = cnt as u64;
    }
    let shared_buff_data = bricks_get_shared_pointer(RET_CODE_BYTES + (u64::BITS as u64) / 8);
    bricks_memcpy(shared_buff_data, buff, cnt);
    bricks_gate_call();
    SUCCESS
}

pub fn bricks_read_shared_handler(buff: *mut c_char, cnt: u32) -> u64 {
    let shared_buff_data = bricks_get_shared_pointer(RET_CODE_BYTES);
    bricks_memcpy(buff, shared_buff_data, cnt);
    SUCCESS
}

pub fn bricks_sbrk_handler(num_bytes: usize) -> u64 {
    alloc_user(num_bytes as u64)
}

pub fn bricks_brk_handler(mem: *mut c_void) -> u64 {
    free_user(VirtualAddr::new(mem as u64))
}

// ———————————————————————————————— Save/restore syscalls ————————————————————————————————— //

use super::tyche_api::enclave_attestation_tyche;
use super::VirtualAddr;
static mut MSR_VAL: u64 = 0;
pub fn bricks_save_syscalls() {
    let msr_lstar = x86_64::registers::model_specific::Msr::new(LSTAR as u32);
    unsafe {
        MSR_VAL = msr_lstar.read();
    }
}

extern "C" {
    fn bricks_syscall_entry();
}

pub fn bricks_syscalls_init() {
    let mut msr_lstar = x86_64::registers::model_specific::Msr::new(LSTAR as u32);
    let handler_addr = bricks_syscall_entry as u64;
    unsafe {
        msr_lstar.write(handler_addr);
    }

    let mut msr_star = x86_64::registers::model_specific::Msr::new(STAR as u32);
    unsafe {
        msr_star.write(STAR_CONST);
    }
}

pub fn bricks_restore_syscalls() {
    let mut msr_lstar = x86_64::registers::model_specific::Msr::new(LSTAR as u32);
    unsafe {
        msr_lstar.write(MSR_VAL);
    }
}

// ——————————————————————————————— Syscall related constants ———————————————————————————————— //

/// /// STAR - register to set Ring 0 and Ring 3 segment base
pub const STAR: u64 = 0xC0000081;
pub const USER_BASE: u64 = 0x13;
pub const KERNEL_BASE: u64 = 0x8;
pub const STAR_CONST: u64 = 0 + (USER_BASE << 48) + (KERNEL_BASE << 32);
/// /// The RIP syscall entry for 64 bit software.
pub const LSTAR: u64 = 0xC0000082;
/// Mask for the low/high bits of msr.
pub const MASK32: u64 = 0xFFFFFFFF;
