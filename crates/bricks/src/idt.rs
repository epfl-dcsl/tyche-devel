use lazy_static::lazy_static;
use x86_64::structures::idt::InterruptDescriptorTable;

use crate::gdt;
use crate::interrupts_handlers::{
    bricks_divide_zero_handler_x86, bricks_x86_64_handler, bricks_x86_64_handler_double,
};
lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.divide_error
            .set_handler_fn(bricks_divide_zero_handler_x86);
        idt.debug.set_handler_fn(bricks_x86_64_handler);
        unsafe {
            idt.double_fault
                .set_handler_fn(bricks_x86_64_handler_double)
                .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
        }
        idt
    };
}

pub fn bricks_init_idt() {
    IDT.load();
}
