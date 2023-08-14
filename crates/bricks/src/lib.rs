mod interrupts;
pub mod interrupts_handlers;
pub mod syscall_handlers;
mod syscalls;

#[no_mangle]
pub extern "C" fn rust_function(a: u32, b: u32) -> u32 {
    a - b
}
