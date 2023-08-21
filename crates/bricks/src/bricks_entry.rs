use crate::gate_calls::{current_frame, BricksFrame};
use crate::gdt::bricks_init_gdt;
use crate::idt::bricks_init_idt;
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
