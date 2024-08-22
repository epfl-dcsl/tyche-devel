//! List of valid monitor calls.

// TODO: Because Risc-V is not implemented yet we allow dead code on that platform.
// Remove this once the Risc-V version is implemented.
#![cfg_attr(target_arch = "riscv64", allow(dead_code))]

//luca: definition of "vmcalls" from dom0 to tyche

pub const CREATE_DOMAIN: usize = 1;
pub const SEAL_DOMAIN: usize = 2;
pub const SEND: usize = 3;
pub const SEGMENT_REGION: usize = 4;
pub const REVOKE: usize = 5;
pub const DUPLICATE: usize = 6;
pub const ENUMERATE: usize = 7;
pub const SWITCH: usize = 8;
pub const EXIT: usize = 9;
pub const DEBUG: usize = 10;
pub const CONFIGURE: usize = 11;
pub const SEND_REGION: usize = 12;
pub const CONFIGURE_CORE: usize = 13;
pub const GET_CONFIG_CORE: usize = 14;
pub const ALLOC_CORE_CONTEXT: usize = 15;
pub const READ_ALL_GP: usize = 16;
pub const WRITE_ALL_GP: usize = 17;
pub const WRITE_FIELDS: usize = 18;
pub const SELF_CONFIG: usize = 19;
// TODO: remove deadcode at some point
pub const _ENCLAVE_ATTESTATION: usize = 20;
pub const REVOKE_ALIASED_REGION: usize = 21;
pub const SERIALIZE_ATTESTATION: usize = 22;
/// For benchmarks to measure the cost of communication with tyche.
pub const _TEST_CALL: usize = 30;
pub const GET_HPAS: usize = 31;
pub const SEND_REGION_REPEAT: usize = 32;
/// dom0 sends data to tyche
pub const SEND_DATA: usize = 33;
/// don1 polls data from tyche
pub const GET_DATA: usize = 34;
pub const PV_IOMMU: usize = 35;
