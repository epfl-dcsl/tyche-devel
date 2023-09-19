use crate::arch::syscall_handlers::bricks_sbrk_handler;
use crate::arch::tyche_api::enclave_attestation_tyche;
use crate::bricks_structs::AttestationResult;
use crate::bricks_utils::bricks_print;

// exceptions written in assembly, not to put too many asm blocks here
extern "C" {
    fn bricks_divide_by_zero_exception();
    fn bricks_int_exception();
}

// function to choose one of the above exceptions
pub fn bricks_make_exception() {
    unsafe {
        bricks_divide_by_zero_exception();
        bricks_int_exception();
    }
}

// function that tests memory management
// based on number of pages granted to Bricks
// it should print NULL at some point
pub fn bricks_test_mm() {
    let mut prev: u64 = 0;
    let mut next: u64;
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

// function to test the attestation
pub fn bricks_test_attestation() {
    let nonce = 0x123;
    let mut att_res = AttestationResult::default();
    enclave_attestation_tyche(nonce, &mut att_res);
}

// testing the print inside the Bricks
pub fn bricks_test_print(str_print: &'static str) {
    bricks_print(str_print);
}

// Same testing as user_main, just producing everything from Bricks (kernel mode)
pub fn bricks_testing() {
    bricks_test_print("Test inside Bricks is starting...");
    bricks_test_attestation();
    bricks_test_mm();
    bricks_test_print("Test inside Bricks is ending...");
}
