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

pub fn bricks_interrupt_setup() {
    bricks_init_gdt();
    bricks_init_idt();
}

pub fn bricks_syscals_setup() {
    bricks_save_syscalls();
    bricks_syscalls_init();
}

pub fn bricks_init_transition() {
    x86_64_transition_setup();
}

pub fn halt() {
    x86_64::instructions::hlt();
}

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
