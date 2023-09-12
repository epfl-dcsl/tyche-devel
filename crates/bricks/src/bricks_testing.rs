use crate::arch::syscall_handlers::{bricks_attest_enclave_handler, bricks_sbrk_handler};
use crate::bricks_utils::bricks_print;

extern "C" {
    fn bricks_divide_by_zero_exception();
    fn bricks_int_exception();
}

pub fn bricks_make_exception() {
    unsafe {
        bricks_divide_by_zero_exception();
        // bricks_int_exception();
    }
}

pub fn bricks_test_mm() {
    let mut prev: u64 = 0;
    let mut next: u64 = 0;
    let iters = 10;
    let num_bytes: usize = 100;
    for _ in 0..iters {
        next = bricks_sbrk_handler(num_bytes as usize); // one page
        if next == prev {
            bricks_print("NULL");
        } else {
            bricks_print("Good alloc");
        }
        prev = next;
    }
}

pub fn bricks_test_attestation() {
    let nonce = 0x123;
    bricks_attest_enclave_handler(nonce);
}

pub fn bricks_test_print(str_print: &'static str) {
    bricks_print(str_print);
}

pub fn bricks_testing() {
    // bricks_make_exception();
    bricks_test_attestation();
    bricks_test_mm();
    bricks_test_print("Tyche");
}
