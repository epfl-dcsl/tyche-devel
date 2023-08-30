use self::gdt::bricks_init_gdt;
use self::idt::bricks_init_idt;
use self::syscall_handlers::{bricks_save_syscalls, bricks_syscalls_init};

pub mod gdt;
pub mod idt;
pub mod interrupt_handlers;
pub mod page_table_mapper;
pub mod segments;
pub mod syscall_handlers;
pub mod tyche_api;

pub fn bricks_interrupt_setup() {
    bricks_init_gdt();
    bricks_init_idt();
}

pub fn bricks_syscals_setup() {
    bricks_save_syscalls();
    bricks_syscalls_init();
}

pub fn halt() {
    x86_64::instructions::hlt();
}
