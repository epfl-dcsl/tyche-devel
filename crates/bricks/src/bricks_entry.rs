use crate::allocator::page_table_mapper;
use crate::gdt::bricks_init_gdt;
use crate::idt::bricks_init_idt;
use crate::shared_buffer::bricks_get_default_shared_buffer;
use crate::syscall_handlers::{bricks_save_syscalls, bricks_syscalls_init};

pub fn bricks_interrupt_setup() {
    bricks_init_gdt();
    bricks_init_idt();
}

pub fn interrupt_setup() {
    bricks_interrupt_setup();
}

pub fn syscall_setup() {
    bricks_save_syscalls();
    bricks_syscalls_init();
}

pub fn setup_physical_offset() {
    let phys_off: u64;
    unsafe {
        phys_off = *(bricks_get_default_shared_buffer() as *mut u64);
    }
    page_table_mapper::set_physical_offset(phys_off);
}
