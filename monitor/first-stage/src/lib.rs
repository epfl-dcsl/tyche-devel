#![no_std]
#![cfg_attr(test, no_main)]
#![feature(custom_test_frameworks)]
#![feature(exclusive_range_pattern)]
#![feature(alloc_error_handler)]
#![feature(abi_x86_interrupt)]
#![feature(const_mut_refs)]
#![feature(naked_functions)]
#![feature(atomic_from_mut)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use core::panic::PanicInfo;

use bootloader::boot_info::FrameBuffer;
use stage_two_abi::VgaInfo;
use vmx;

pub mod acpi;
pub mod acpi_handler;
pub mod allocator;
pub mod cpu;
pub mod elf;
pub mod gdt;
pub mod getsec;
pub mod guests;
pub mod idt;
pub mod mmu;
pub mod print;
pub mod second_stage;
pub mod segments;
pub mod serial;
pub mod smp;
pub mod smx;

pub use vmx::{GuestPhysAddr, GuestVirtAddr, HostPhysAddr, HostVirtAddr};

pub use crate::mmu::init as init_memory;

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
    // Install GDT and IDT on the BSP
    cpu::init();
    idt::init();
}

/// Initialize display device.
pub fn init_display(_buffer: &'static mut FrameBuffer) -> VgaInfo {
    let mut vga_info = VgaInfo::no_vga();
    vga_info.is_valid = false;
    #[cfg(feature = "vga")]
    {
        let info = _buffer.info();
        let h_rez = info.horizontal_resolution;
        let v_rez = info.vertical_resolution;
        let stride = info.stride;
        let bytes_per_pixel = info.bytes_per_pixel;
        let framebuffer = _buffer.buffer_mut().as_mut_ptr();
        let len = _buffer.buffer_mut().len();
        let writter = vga::Writer::new(_buffer.buffer_mut(), h_rez, v_rez, stride, bytes_per_pixel);
        vga::init_print(writter);
        vga_info = VgaInfo {
            is_valid: true,
            framebuffer,
            len,
            h_rez,
            v_rez,
            stride,
            bytes_per_pixel,
        }
    }
    vga_info
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
    hlt_loop();
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
