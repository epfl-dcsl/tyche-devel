//! List of valid monitor calls.

// TODO: Because Risc-V is not implemented yet we allow dead code on that platform.
// Remove this once the Risc-V version is implemented.
#![cfg_attr(target_arch = "riscv64", allow(dead_code))]

pub const CREATE_DOMAIN: usize = 1;
pub const SEAL_DOMAIN: usize = 2;
pub const _SHARE: usize = 3;
pub const SEND: usize = 4;
pub const SEGMENT_REGION: usize = 5;
pub const REVOKE: usize = 6;
pub const DUPLICATE: usize = 7;
pub const ENUMERATE: usize = 8;
pub const SWITCH: usize = 9;
pub const EXIT: usize = 10;
pub const DEBUG: usize = 11;
pub const CONFIGURE: usize = 12;
pub const SEND_REGION: usize = 13;
pub const CONFIGURE_CORE: usize = 14;
pub const GET_CONFIG_CORE: usize = 15;
pub const ALLOC_CORE_CONTEXT: usize = 16;
pub const READ_ALL_GP: usize = 17;
pub const WRITE_ALL_GP: usize = 18;
pub const WRITE_FIELDS: usize = 19;
pub const SELF_CONFIG: usize = 20;
pub const ENCLAVE_ATTESTATION: usize = 21;
