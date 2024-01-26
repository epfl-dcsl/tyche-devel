//! RISC-V 64 implementation

use core::arch::asm;
use core::fmt;
use core::fmt::Write;

use riscv_utils::SERIAL_PORT_BASE_ADDRESS;
use uart_16550::MmioSerialPort;
use spin::Mutex;

use crate::ExitCode;

//static mut SERIAL_PORT: Option<MmioSerialPort> = None;

/// Internal function used to print to stdout when running in Qemu.
pub fn _print(_args: fmt::Arguments) {
    
    static mut SERIAL_PORT: Option<Mutex<MmioSerialPort>> = None; 

    unsafe {
                
        let mut serial_port = Mutex::new(MmioSerialPort::new(SERIAL_PORT_BASE_ADDRESS));
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

    /* static mut SERIAL_PORT: Option<MmioSerialPort> = None;

    unsafe {
        let mut serial_port = MmioSerialPort::new(SERIAL_PORT_BASE_ADDRESS);
        serial_port.init();
        SERIAL_PORT = Some(serial_port);

        if let Some(ref mut serial_port) = SERIAL_PORT {
            serial_port
                .write_fmt(_args)
                .expect("Printing to serial failed");
        }
    } */ 
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
