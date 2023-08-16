use crate::gate_calls::{current_frame, BricksFrame};
use crate::gdt::init_gdt;
use crate::idt::init_idt;

extern "C" {
    fn setup_interrupts_syscalls();
}

pub fn bricks_interrupt_setup() {
    init_gdt();
    init_idt();
}

pub fn C_interrupt_setup() {
    unsafe {
        setup_interrupts_syscalls();
    }
}

pub fn interrupt_setup() {
    // bricks_interrupt_setup();
    C_interrupt_setup();
}
