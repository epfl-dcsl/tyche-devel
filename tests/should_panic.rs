#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

use kernel::{print, println, qemu};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    test_main();

    kernel::hlt_loop();
}
pub fn test_runner(tests: &[&dyn Fn()]) {
    println!("Running {} tests", tests.len());
    for test in tests {
        test();
        println!("[test did not panic]");
        qemu::exit(qemu::ExitCode::Failure);
    }
    qemu::exit(qemu::ExitCode::Success);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    println!("[ok]");
    qemu::exit(qemu::ExitCode::Success);
}

#[test_case]
fn should_fail() {
    print!("should_panic::should_fail...\t");
    assert_eq!(0, 1);
}
