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

// ——————————————————————————————— Syscalls defined by us ———————————————————————————————— //
pub const NUM_OF_SYSCALLS: usize = 5;
pub const ATTEST_ENCLAVE: usize = 1000;
pub const PRINT: usize = 1001;
pub const GATE_CALL: usize = 1002;
pub const WRITE_SHARED: usize = 1003;
pub const READ_SHARED: usize = 1004;
// ——————————————————————————————— Standard syscalls ———————————————————————————————— //
/// Linux syscalls
pub const LINUX_MMAP: usize = 9;

// TODO set proper values for the system calls we want
