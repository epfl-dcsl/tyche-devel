#![no_std]

// --------------------------------- TYCHE - QEMU Config --------------------------------------- //

// TYCHE_START_ADDRESS: 0x80250000

#[cfg(not(feature = "visionfive2"))]
use riscv_utils::{PCI_BASE_ADDRESS, PCI_SIZE, SIFIVE_TEST_SYSCON_BASE_ADDRESS};

// tyche stack pointer
#[cfg(not(feature = "visionfive2"))]
pub static TYCHE_STACK_POINTER: [usize; 4] = [0x80390000, 0x8038b000, 0x80386000, 0x80381000];

#[cfg(not(feature = "visionfive2"))]
pub const DOM0_ROOT_REGION_START: usize = 0x80400000;
#[cfg(not(feature = "visionfive2"))]
pub const DOM0_ROOT_REGION_END: usize = 0x800000000;

#[cfg(not(feature = "visionfive2"))]
pub const DOM0_ROOT_REGION_2_START: usize = SIFIVE_TEST_SYSCON_BASE_ADDRESS;
#[cfg(not(feature = "visionfive2"))]
pub const DOM0_ROOT_REGION_2_END: usize = PCI_BASE_ADDRESS + PCI_SIZE;

// --------------------------------- TYCHE - VF2 Config --------------------------------------- //

// TYCHE_START_ADDRESS: 0x23fa00000;

#[cfg(feature = "visionfive2")]
pub const TYCHE_STACK_POINTER: [usize; 5] = [
    0x23ffff000,
    0x23fffb000,
    0x23fff8000,
    0x23fff4000,
    0x23fff0000,
];

#[cfg(feature = "visionfive2")]
pub const DOM0_ROOT_REGION_START: usize = 0x0;
#[cfg(feature = "visionfive2")]
pub const DOM0_ROOT_REGION_END: usize = 0x23fa00000;

#[cfg(feature = "visionfive2")]
pub const DOM0_ROOT_REGION_2_START: usize = 0x240000000;
#[cfg(feature = "visionfive2")]
pub const DOM0_ROOT_REGION_2_END: usize = 0xffffffffffffffff;

// --------------------------------- TYCHE Manifest --------------------------------------- //

#[repr(C)]
pub struct RVManifest {
    pub next_arg1: usize,
    pub next_addr: usize,
    pub next_mode: usize,
    pub coldboot_hartid: usize,
    pub num_harts: usize,
}
