#![no_std]
#![cfg_attr(test, no_main)]
#![feature(custom_test_frameworks)]
#![feature(exclusive_range_pattern)]
#![feature(alloc_error_handler)]
#![feature(abi_x86_interrupt)]
#![feature(const_mut_refs)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use core::panic::PanicInfo;

use bootloader::boot_info::FrameBuffer;

pub mod allocator;
pub mod gdt;
pub mod guests;
pub mod interrupts;
pub mod memory;
pub mod print;
pub mod qemu;
pub mod serial;
pub mod vmx;

#[cfg(feature = "vga")]
pub mod vga;

pub use memory::init as init_memory;

// Entry point for `cargo test`
#[cfg(test)]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    init();
    test_main();

    hlt_loop();
}

/// Initialize the kernel environment.
pub fn init() {
    // Initialize description tables
    gdt::init();
    interrupts::init_idt();

    // Initialize hardware interrupt
    // unsafe { interrupts::PICS.lock().initialize() };
    // x86_64::instructions::interrupts::enable();
}

/// Initialize display device.
pub fn init_display(_buffer: &'static mut FrameBuffer) {
    #[cfg(feature = "vga")]
    return vga::init(_buffer);
}

/// An infinite loop that causes the CPU to halt between interrupts.
pub fn hlt_loop() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

#[alloc_error_handler]
fn alloc_error_handler(layout: alloc::alloc::Layout) -> ! {
    panic!("allocation error: {:?}", layout)
}

// —————————————————————————————————— Test —————————————————————————————————— //

pub trait Testable {
    fn run(&self) -> ();
}

impl<T> Testable for T
where
    T: Fn(),
{
    fn run(&self) {
        print!("{}...\t", core::any::type_name::<T>());
        self();
        println!("[ok]");
    }
}

/// A custom test runner for the kernel.
pub fn test_runner(tests: &[&dyn Testable]) {
    println!("Running {} tests", tests.len());
    for test in tests {
        test.run();
    }

    qemu::exit(qemu::ExitCode::Success);
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info);
}

/// A custom panic handler for kernel testing.
pub fn test_panic_handler(info: &PanicInfo) -> ! {
    println!("[failed]\n");
    println!("Error: {}\n", info);
    qemu::exit(qemu::ExitCode::Failure);
}

#[cfg(test)]
mod tests {
    #[test_case]
    fn test() {
        assert_eq!(1, 1);
    }

    #[test_case]
    fn breakpoint_exception() {
        x86_64::instructions::interrupts::int3();
    }
}
