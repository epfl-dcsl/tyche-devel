//! Second-stage
#![no_std]
#![feature(fn_align)]
#![feature(naked_functions)]
#![feature(isqrt)]

pub mod allocator;
pub mod attestation_domain;
mod calls;
pub mod debug;
pub mod error;
pub mod monitor;
pub mod statics;
mod sync;

#[cfg(target_arch = "riscv64")]
pub mod riscv;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub mod arch {
    pub use crate::x86_64::*;
}

#[cfg(target_arch = "riscv64")]
pub mod arch {
    pub use crate::riscv::*;
}

/// Special return values supplied by the monitor.
#[repr(usize)]
pub enum MonitorErrors {
    DomainRevoked = 66,
}

// helper functions.

pub fn align_down(val: usize, alignment: usize) -> usize {
    assert!(
        alignment.is_power_of_two(),
        "`alignment` must be a power of two"
    );
    let aligned = val & !(alignment - 1);
    aligned
}

pub fn align_up(val: usize, alignment: usize) -> usize {
    assert!(
        alignment.is_power_of_two(),
        "`alignment` must be a power of two"
    );
    return (val + alignment - 1) & !(alignment - 1);
}
