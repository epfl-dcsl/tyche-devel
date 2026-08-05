#![no_std]

use core::arch::asm;
use core::fmt::Write;
use core::ptr::read_volatile;
use core::{fmt, ptr};

use spin::Mutex;

pub const SERIAL_PORT_BASE_ADDRESS: usize = 0x4060_0000;
const REG_TX: usize = 0x04;
const REG_RX: usize = 0x00; 
const REG_STATUS: usize = 0x08; 
const REG_CONTROL: usize = 0x0C; 
const UART_TX_FULL: u8 = (1 << 0x3);
const UART_RX_VALID: u16 = (1 << 0x0);

// pub const SERIAL_PORT_BASE_ADDRESS: usize = 0x1000_0000;

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
            let status_addr = self.serial_port_base_addr + REG_STATUS;

            let mut status_value: u8 = UART_TX_FULL; 
            while(status_value == UART_TX_FULL)
            {
                status_value = 
                    ptr::read_volatile(
                        (status_addr) as *const u8 // <-- The necessary cast
                    );
            }
            ptr::write_volatile((self.serial_port_base_addr + REG_TX) as *mut char, c);


            // ptr::write_volatile((self.serial_port_base_addr) as *mut char, c);
            // for _n in 1..10000001 {
            //     asm!("nop");
            // }
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

pub fn read_char() -> i32 {
    unsafe {
        let status = ptr::read_volatile((SERIAL_PORT_BASE_ADDRESS + REG_STATUS) as *const u16);
        if (status & UART_RX_VALID) != 0 {
            return ptr::read_volatile((SERIAL_PORT_BASE_ADDRESS + REG_RX) as *const u8) as i32;
        }
    }
    return -1;
}
