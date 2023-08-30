use lazy_static::lazy_static;
use x86_64::structures::idt::InterruptDescriptorTable;
use x86_64::structures::DescriptorTablePointer;

use crate::arch::gdt;
use crate::arch::interrupt_handlers::*;

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

// ———————————————————————————————— Save/restore idt ————————————————————————————————— //
static mut IDT_SAVE: Option<DescriptorTablePointer> = None;

pub fn bricks_save_idt() {
    unsafe {
        IDT_SAVE = Some(x86_64::instructions::tables::sidt());
    }
}

pub fn bricks_restore_idt() {
    unsafe {
        if let Some(idt_s) = IDT_SAVE {
            x86_64::instructions::tables::lidt(&idt_s);
        }
    }
}
