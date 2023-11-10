#![no_std]

use core::arch::asm;
use core::fmt::Write;
use core::{fmt, ptr};

use spin::Mutex;

pub const SERIAL_PORT_BASE_ADDRESS: usize = 0x1000_0000;

pub static WRITER: Mutex<Writer> = Mutex::new(Writer::new(SERIAL_PORT_BASE_ADDRESS));

pub struct Writer {
    serial_port_base_addr: usize,
}

impl Writer {
    pub const fn new(serial_port_base_addr: usize) -> Self {
        Writer {
            serial_port_base_addr,
        }
    }

    fn write_char(&mut self, c: char) {
        unsafe {
            ptr::write_volatile(self.serial_port_base_addr as *mut char, c);
            for _n in 1..100001 {
                asm!("nop");
            }
        }
    }
}

impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            self.write_char(c);
        }
        Ok(())
    }
}

pub fn _print(args: fmt::Arguments) {
    //disable interrupts
    let mut writer = WRITER.lock();
    writer.write_fmt(args).unwrap();
    drop(writer);
    //enable interrupts
}

pub fn write_char(c: char) {
    let mut writer = WRITER.lock();
    writer.write_char(c);
    drop(writer);
}
