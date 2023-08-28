use crate::allocator::page_table_mapper;
use crate::bricks_const::RET_CODE_BYTES;
use crate::gate_calls::bricks_gate_call;
use crate::gdt::bricks_init_gdt;
use crate::idt::bricks_init_idt;
use crate::shared_buffer::{bricks_get_default_shared_buffer, bricks_write_ret_code, bricks_get_shared_pointer, bricks_debug};
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