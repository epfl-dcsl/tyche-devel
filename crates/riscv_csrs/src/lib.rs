#![no_std]

//mstatus register fields. mask for fields with width > 1 bit.
pub mod mstatus {
    pub const MPP_LOW: usize = 11;
    pub const MPP_HIGH: usize = 12;
    pub const MPP_MASK: usize = 0x3; // 2 bits
    pub const MPIE: usize = 7;
    pub const MPRV: usize = 17;
    pub const MXR: usize = 19;
}

//MEDELEG register fields or mcause register valid values.
pub mod mcause {
    pub const INSTRUCTION_ACCESS_FAULT: usize = 1;
    pub const ILLEGAL_INSTRUCTION: usize = 2;
    pub const LOAD_ADDRESS_MISALIGNED: usize = 4;
    pub const LOAD_ACCESS_FAULT: usize = 5;
    pub const STORE_ADDRESS_MISALIGNED: usize = 6;
    pub const ECALL_FROM_UMODE: usize = 8;
    pub const STORE_ACCESS_FAULT: usize = 7;
    pub const ECALL_FROM_SMODE: usize = 9;
    pub const INSTRUCTION_PAGE_FAULT: usize = 12;
    pub const LOAD_PAGE_FAULT: usize = 13;
    pub const STORE_PAGE_FAULT: usize = 15;
    pub const MSWI: usize = (1 << 63) | 3;
    pub const MTI: usize = (1 << 63) | 7;
    pub const MEI: usize = (1 << 63) | 11;
}

pub mod pmpcfg {
    pub const READ: usize = 0;
    pub const WRITE: usize = 1;
    pub const EXECUTE: usize = 2;
}
