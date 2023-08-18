use core::arch::asm;

use crate::bricks_const::SUCCESS;

// #[derive(Default)]
pub struct TycheCallArgs {
    vmmcall: usize,

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
            inout("eax") args.vmmcall as usize => args.res,
            inout("edi") args.arg_1 => args.value_1,
            inout("esi") args.arg_2 => args.value_2,
            inout("edx") args.arg_3 => args.value_3,
            inout("ecx") args.arg_4 => args.value_4,
            inout("r8") args.arg_5 => args.value_5,
            inout("r9") args.arg_6 => args.value_6,
        );
    }
}

// ———————————————————————————————— Helpers to return make tyche calls and return result ————————————————————————————————— //

const ENCLAVE_ATTESTATION: usize = 14;
const CALC_REPORT: usize = 0;
const READ_REPORT: usize = 1;
pub fn enclave_attestation_tyche(nonce: u32) -> u32 {
    let mut call_args = TycheCallArgs::default();
    call_args.vmmcall = ENCLAVE_ATTESTATION;
    call_args.arg_1 = nonce as usize;
    call_args.arg_2 = CALC_REPORT;
    call_tyche(&mut call_args);
    // Do something with result
    call_args.clean_args();
    call_args.vmmcall = ENCLAVE_ATTESTATION;
    call_args.arg_1 = nonce as usize;
    call_args.arg_2 = READ_REPORT;
    call_tyche(&mut call_args);
    // Do something with result
    // TODO
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
