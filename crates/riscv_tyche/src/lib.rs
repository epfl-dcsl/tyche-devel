#![no_std]

use riscv_utils::{SIFIVE_TEST_SYSCON_BASE_ADDRESS, PCI_BASE_ADDRESS, PCI_SIZE};

// --------------------------------- TYCHE - QEMU Config --------------------------------------- //

//tyche monitor base address and size
// Neelu: The following two don't matter anymore? Also VF2 tyche start addr?
#[cfg(not(feature = "visionfive2"))]
pub const TYCHE_START_ADDRESS: usize = 0x80250000;  

//tyche stack pointer
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

#[cfg(feature = "visionfive2")]
pub const TYCHE_START_ADDRESS: usize = 0x23fa00000;

#[cfg(feature = "visionfive2")]
pub const TYCHE_STACK_POINTER: [usize; 5] = [0x23ffff000, 0x23fffb000, 0x23fff8000, 0x23fff4000, 0x23fff0000];

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

// For the VF2 board  
/* pub const VF2_TYCHE_START_ADDRESS: usize = 0x23fa00000;
pub const VF2_TYCHE_STACK_POINTER: [usize; 5] = [0x23ffff000, 0x23fffb000, 0x23fff8000, 0x23fff4000, 0x23fff0000];

//pub const VF2_DOM0_ROOT_REGION_START: usize = 0x40200000;
pub const VF2_DOM0_ROOT_REGION_START: usize = 0x0;
pub const VF2_DOM0_ROOT_REGION_END: usize = 0x23fa00000;

//pub const VF2_DOM0_ROOT_REGION_2_START: usize = 0x23fffffff;
pub const VF2_DOM0_ROOT_REGION_2_START: usize = 0x240000000;
//pub const VF2_DOM0_ROOT_REGION_2_END: usize = 0x242000000;
pub const VF2_DOM0_ROOT_REGION_2_END: usize = 0xffffffffffffffff;
//pub const VF2_DOM0_ROOT_REGION_END: usize = 0xffffffffffffffff;
 */ 
//This one includes cache controller, plic, pcie, syscon. (Basically overprivileged to confine it to 1 PMP)
//pub const VF2_DOM0_ROOT_REGION_2_START: usize = 0x2010000;  
//pub const VF2_DOM0_ROOT_REGION_2_END: usize = 0x2bffffff;
//
//Question is: Do I care about protecting opensbi's memory at this point? No - clear it out and
//then let linux have it back! Basically, doesn't need to be reserved in the FDT either!  
//Then we should just use 1 PMP entry (start: 0x0, end: tyche_start_addr)

//pub const VF2_DOM0_ROOT_REGION_2_START: usize = 0x0; 
//pub const VF2_DOM0_ROOT_REGION_2_END: usize = 0x3fffffff;
