use crate::gate_calls::{current_frame, BricksFrame};
use crate::gdt::bricks_init_gdt;
use crate::idt::bricks_init_idt;

extern "C" {
    fn setup_interrupts_syscalls();
}

pub fn bricks_interrupt_setup() {
    bricks_init_gdt();
    bricks_init_idt();
}

pub fn c_interrupt_setup() {
    unsafe {
        setup_interrupts_syscalls();
    }
}

pub fn interrupt_setup() {
    bricks_interrupt_setup();
    // c_interrupt_setup();
}
