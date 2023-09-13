use core::ffi::c_char;

use crate::arch::syscall_handlers::bricks_print_handler;
use crate::bricks_structs::AttestationResult;

pub fn bricks_memcpy(dst: *mut c_char, src: *mut c_char, cnt: u32) {
    let mut dst_cp = dst;
    let mut src_cp = src;
    for _ in 0..cnt {
        unsafe {
            *dst_cp = *src_cp;
        }
        dst_cp = ((dst_cp as u64) + 1) as *mut c_char;
        src_cp = ((src_cp as u64) + 1) as *mut c_char;
    }
}

pub fn bricks_strlen(str: *mut c_char) -> u32 {
    let mut buff_cpy = str;
    let mut cnt_chars = 0;
    loop {
        cnt_chars += 1;
        unsafe {
            if *buff_cpy == ('\0' as i8) {
                break;
            }
        }
        buff_cpy = ((buff_cpy as u64) + 1) as *mut c_char;
    }
    cnt_chars
}

pub fn bricks_min(a: usize, b: usize) -> usize {
    if a > b {
        b
    } else {
        a
    }
}

const ARR_SZ: usize = 256;
pub fn bricks_print(str_print: &'static str) {
    let mut char_arr: [u8; ARR_SZ] = [0; ARR_SZ];
    let mut i: usize = 0;
    for chr in str_print.chars() {
        char_arr[i] = chr as u8;
        i += 1;
    }
    char_arr[i] = '\0' as u8;
    bricks_print_handler(char_arr.as_ptr() as *mut i8);
}

pub fn copy_to_pub_key(num: u64, index: usize, result_struct: &mut AttestationResult) {
    let index_end = index + u64::BITS as usize / 8;
    let slice = &mut result_struct.pub_key[index..index_end];
    slice.copy_from_slice(&u64::to_le_bytes(num));
}

pub fn copy_to_signed_data(num: u64, index: usize, result_struct: &mut AttestationResult) {
    let index_end = index + u64::BITS as usize / 8;
    let slice = &mut result_struct.signed_enclave_data[index..index_end];
    slice.copy_from_slice(&u64::to_le_bytes(num));
}
