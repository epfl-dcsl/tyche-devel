use core::arch::asm;
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
pub fn bricks_syscall_handler() {
    if check_syscalls_kill() {
        exit_gate();
    }
    // Guard to make sure cpu halts if someone calls syscall - for now
    x86_64::instructions::hlt();
    let mut rax: usize;
    let _r10: usize;
    let rdi: usize;
    let rsi: usize;
    let _rdx: usize;
    unsafe {
        asm!("mov {}, rax", out(reg) rax);
        asm!("mov {}, rdi", out(reg) rdi);
        asm!("mov {}, rsi", out(reg) rsi);
        asm!("mov {}, rdx", out(reg) _rdx);
        asm!("mov {}, r10", out(reg) _r10);
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
        _ => {
            _result = FAILURE;
            unsafe {
                asm!("hlt");
            }
        }
    }
    // TODO(papa) return from syscall (user)
    // unsafe {
    //     asm!("sysret");
    // }
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
        msr_lstar.write(MSR_VAL);
    }
}

// ——————————————————————————————— Syscall related constants ———————————————————————————————— //
/// /// The RIP syscall entry for 64 bit software.
pub const LSTAR: u64 = 0xC0000082;
/// The RIP syscall entry for compatibility mode
pub const CSTAR: u64 = 0xC0000083;
/// low 32 bits syscall flag mask, if a bit is set, clear the corresponding one
/// in RFLAGS.
pub const SFMASK_VAL: u64 = 0xC0000084;
/// Mask for the low/high bits of msr.
pub const MASK32: u64 = 0xFFFFFFFF;
