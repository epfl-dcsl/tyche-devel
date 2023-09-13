use core::arch::asm;

use crate::bricks_const::SUCCESS;
use crate::bricks_structs::{AttestationResult, CALC_REPORT, READ_REPORT};
use crate::bricks_utils::{copy_to_pub_key, copy_to_signed_data};

pub struct TycheCallArgs {
    vmmcall: usize,
    // Args
    arg_1: usize,
    arg_2: usize,
    arg_3: usize,
    arg_4: usize,
    arg_5: usize,
    arg_6: usize,
    // Results.
    res: usize,
    value_1: usize,
    value_2: usize,
    value_3: usize,
    value_4: usize,
    value_5: usize,
    value_6: usize,
}

pub fn call_tyche(args: &mut TycheCallArgs) {
    unsafe {
        asm!(
            "vmcall",
            inout("rax") args.vmmcall as usize => args.res,
            inout("rdi") args.arg_1 => args.value_1,
            inout("rsi") args.arg_2 => args.value_2,
            inout("rdx") args.arg_3 => args.value_3,
            inout("rcx") args.arg_4 => args.value_4,
            inout("r8") args.arg_5 => args.value_5,
            inout("r9") args.arg_6 => args.value_6,
        );
    }
}

// ———————————————————————————————— Helpers to return make tyche calls and return result ————————————————————————————————— //
const ENCLAVE_ATTESTATION: usize = 14;
pub fn enclave_attestation_tyche(nonce: u64, result_struct: &mut AttestationResult) -> u64 {
    let mut call_args = TycheCallArgs::default();

    // First call to Tyche
    call_args.vmmcall = ENCLAVE_ATTESTATION;
    call_args.arg_1 = nonce as usize;
    call_args.arg_2 = CALC_REPORT;
    call_tyche(&mut call_args);

    // Copy Tyche response to structure
    copy_to_pub_key(call_args.value_1 as u64, 0, result_struct);
    copy_to_pub_key(call_args.value_2 as u64, 8, result_struct);
    copy_to_pub_key(call_args.value_3 as u64, 16, result_struct);
    copy_to_pub_key(call_args.value_4 as u64, 24, result_struct);
    copy_to_signed_data(call_args.value_5 as u64, 0, result_struct);
    copy_to_signed_data(call_args.value_6 as u64, 8, result_struct);

    call_args.clean_args();

    //Second call to Tyche
    call_args.vmmcall = ENCLAVE_ATTESTATION;
    call_args.arg_1 = nonce as usize;
    call_args.arg_2 = READ_REPORT;
    call_tyche(&mut call_args);

    // Copy Tyche response to structure
    copy_to_signed_data(call_args.value_1 as u64, 16, result_struct);
    copy_to_signed_data(call_args.value_2 as u64, 24, result_struct);
    copy_to_signed_data(call_args.value_3 as u64, 32, result_struct);
    copy_to_signed_data(call_args.value_4 as u64, 40, result_struct);
    copy_to_signed_data(call_args.value_5 as u64, 48, result_struct);
    copy_to_signed_data(call_args.value_6 as u64, 56, result_struct);

    SUCCESS
}

// ———————————————————————————————— Implementation for some functions for TycheCallArgs ————————————————————————————————— //
impl Default for TycheCallArgs {
    fn default() -> Self {
        TycheCallArgs {
            vmmcall: 0,
            arg_1: 0,
            arg_2: 0,
            arg_3: 0,
            arg_4: 0,
            arg_5: 0,
            arg_6: 0,
            res: 0,
            value_1: 0,
            value_2: 0,
            value_3: 0,
            value_4: 0,
            value_5: 0,
            value_6: 0,
        }
    }
}

impl TycheCallArgs {
    pub fn clean_args(&mut self) {
        self.vmmcall = 0;
        self.arg_1 = 0;
        self.arg_2 = 0;
        self.arg_3 = 0;
        self.arg_4 = 0;
        self.arg_5 = 0;
        self.arg_6 = 0;
    }
}
