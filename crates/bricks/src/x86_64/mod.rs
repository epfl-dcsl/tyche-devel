use x86_64::VirtAddr;

use self::gdt::bricks_init_gdt;
use self::idt::bricks_init_idt;
use self::syscall_handlers::{bricks_save_syscalls, bricks_syscalls_init};
use self::transition::x86_64_transition_setup;

pub mod gdt;
pub mod idt;
pub mod interrupt_handlers;
pub mod page_table_mapper;
pub mod segments;
pub mod syscall_handlers;
pub mod transition;
pub mod tyche_api;

// Public functions provided by architecture-dependent part
// RISC-V will need to provide same interface

pub fn bricks_interrupt_setup() {
    bricks_init_gdt();
    bricks_init_idt();
}

pub fn bricks_syscals_setup() {
    bricks_save_syscalls();
    bricks_syscalls_init();
}

pub fn bricks_transition_setup(user_rip: u64, user_rsp: u64) {
    x86_64_transition_setup(user_rip, user_rsp);
}

pub fn halt() {
    x86_64::instructions::hlt();
}

// Wrapper around x86 crate VirtAddr
// Useful for Allocator to work with VirtualAddr (arch-independent)
pub struct VirtualAddr {
    addr: VirtAddr,
}

impl VirtualAddr {
    pub fn new(addr_u64: u64) -> Self {
        VirtualAddr {
            addr: VirtAddr::new(addr_u64),
        }
    }

    pub fn as_u64(&self) -> u64 {
        self.addr.as_u64()
    }
}
