//! x86_64 backend for stage 2

mod arch;
mod context;
mod cpuid_filter;
mod init;
mod perf;
mod platform;
mod state;
mod vmx_helper;

use core::arch::asm;

pub use init::arch_entry_point;
pub use vmx::{ActiveVmcs, VmxError as BackendError};

use crate::debug::qemu::ExitCode;

// —————————————————————————————— x86_64 Arch ——————————————————————————————— //
pub fn cpuid() -> usize {
    let cpuid = unsafe { core::arch::x86_64::__cpuid(0x01) };
    ((cpuid.ebx & 0xffffffff) >> 24) as usize
}

/// Halt the CPU in a spinloop;
pub fn hlt() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

pub fn exit_qemu(exit_code: ExitCode) {
    const QEMU_EXIT_PORT: u16 = 0xf4;

    unsafe {
        let exit_code = exit_code as u32;
        asm!(
            "out dx, eax",
            in("dx") QEMU_EXIT_PORT,
            in("eax") exit_code,
            options(nomem, nostack, preserves_flags)
        );
    }
}
