#![no_std]

//tyche monitor base address and size
pub const TYCHE_START_ADDRESS: usize = 0x80250000;
pub const TYCHE_SIZE_NAPOT: usize = 14;

//tyche stack pointer
//Should be fine as long as Tyche size doesn't exceed half an MB.
//TODO: Need to protect it. Perhaps protect entire 1 MB memory region?
pub static TYCHE_STACK_POINTER: [usize; 4] = [0x80390000, 0x8038b000, 0x80386000, 0x80381000];

#[repr(C)]
pub struct RVManifest {
    pub next_arg1: usize,
    pub next_addr: usize,
    pub next_mode: usize,
    pub coldboot_hartid: usize,
    pub num_harts: usize,
    pub modulus: [u8; 384],
    pub signature: [u8; 384],
    pub attestation: [u8; 129],
}
