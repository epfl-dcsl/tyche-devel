//! Debug Module
//!
//! This module is used for debugging, but is excluded from the TCB when compiling on release mode
//! (it is instead replaced by a stub module wity no-ops).

// ———————————————————————————— Print Facilities ———————————————————————————— //

#[cfg(target_arch = "x86_64")]
pub mod serial {
    #[cfg(not(feature = "vga"))]
    pub use qemu::_print;
    #[cfg(feature = "vga")]
    pub use vga::_print;
}

#[cfg(target_arch = "riscv64")]
pub mod serial {
    pub use qemu::_print;
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::debug::serial::_print(core::format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\r\n"));
    ($($arg:tt)*) => ($crate::print!("{}\r\n", core::format_args!($($arg)*)))
}

// —————————————————————————————————— Qemu —————————————————————————————————— //

pub mod qemu {
    pub use qemu::ExitCode;

    #[cfg(target_arch = "riscv64")]
    use crate::riscv::hlt;
    #[cfg(target_arch = "x86_64")]
    use crate::x86_64::hlt;

    pub fn exit(exit_code: ExitCode) -> ! {
        println!("========= Exiting Second Stage =========");
        println!("{}", exit_code.to_str());
        println!("========================================");

        qemu::exit(exit_code);
        hlt();
    }
}
