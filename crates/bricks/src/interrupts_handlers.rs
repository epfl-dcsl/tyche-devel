use core::arch::asm;

#[no_mangle]
pub extern "C" fn bricks_interrupt_handler() {
    // TODO
    unsafe {
        asm!("cli", "hlt");
    }
}

#[no_mangle]
pub extern "C" fn bricks_division_by_zero_handler() {
    // TODO
    unsafe {
        asm!("cli", "hlt");
    }
}
