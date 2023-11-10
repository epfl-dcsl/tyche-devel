//! RISC-V 64 implementation

use core::arch::asm;
#[cfg(not(feature = "visionfive2"))]
use core::fmt;
#[cfg(not(feature = "visionfive2"))]
use core::fmt::Write;

#[cfg(not(feature = "visionfive2"))]
use spin::Mutex;
#[cfg(not(feature = "visionfive2"))]
pub const SERIAL_PORT_BASE_ADDRESS: usize = 0x1000_0000;
#[cfg(not(feature = "visionfive2"))]
use uart_16550::MmioSerialPort;

use crate::ExitCode;

/// Internal function used to print to stdout when running in Qemu.
#[cfg(not(feature = "visionfive2"))]
pub fn _print(_args: fmt::Arguments) {
    static mut SERIAL_PORT: Option<Mutex<MmioSerialPort>> = None;
    unsafe {
        let serial_port = Mutex::new(MmioSerialPort::new(SERIAL_PORT_BASE_ADDRESS));
        let mut serial = serial_port.lock();
        serial.init();
        drop(serial);

        SERIAL_PORT = Some(serial_port);

        if let Some(ref mut serial_port) = SERIAL_PORT {
            serial_port
                .lock()
                .write_fmt(_args)
                .expect("Printing to serial failed")
        }
    }
}

// —————————————————————————————— Exiting QEMU —————————————————————————————— //

/// Exit QEMU.
pub fn exit(_exit_code: ExitCode) {
    const _QEMU_EXIT_PORT: u16 = 0xf4;

    // TODO
    // Add qemu exit using qemu exit code - refer here: https://github.com/andre-richter/qemu-exit/blob/master/src/riscv64.rs
    // For now just using the loop.

    unsafe {
        // For the case that the QEMU exit attempt did not work, transition into an infinite
        // loop. Calling `panic!()` here is unfeasible, since there is a good chance
        // this function here is the last expression in the `panic!()` handler
        // itself. This prevents a possible infinite loop.
        loop {
            asm!("wfi", options(nomem, nostack));
        }
    }
}
