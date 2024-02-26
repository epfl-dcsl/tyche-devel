#![no_std]

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::{_print, exit};

#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(target_arch = "riscv64")]
pub use riscv64::{_print, exit};

// ———————————————————————————— Print Utilities ————————————————————————————— //

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::_print(core::format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", core::format_args!($($arg)*)));
}

// —————————————————————————————— Exiting QEMU —————————————————————————————— //

/// Qemu exit codes
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u32)]
pub enum ExitCode {
    Success = 0x10,
    Failure = 0x11,
}

impl ExitCode {
    pub fn to_str(self) -> &'static str {
        match self {
            ExitCode::Success => "Success",
            ExitCode::Failure => "Failure",
        }
    }
}
