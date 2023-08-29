// ——————————————————————————————— Syscalls defined by us ———————————————————————————————— //
pub const NUM_OF_SYSCALLS: usize = 7;
pub const ATTEST_ENCLAVE: usize = 1000;
pub const PRINT: usize = 1001;
pub const GATE_CALL: usize = 1002;
pub const WRITE_SHARED: usize = 1003;
pub const READ_SHARED: usize = 1004;
// ——————————————————————————————— Standard syscalls ———————————————————————————————— //
/// Linux syscalls
pub const LINUX_MMAP: usize = 9;

/// Moving this to SBRK and BRK, adjust codes
pub const SBRK: usize = 1005;
pub const BRK: usize = 1006;

// TODO set proper values for the system calls we want
