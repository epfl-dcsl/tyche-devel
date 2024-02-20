// NOTE: All of the constants are directly copied from the x86 crate

use core::arch::asm;

/// Write 64 bits to msr register.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    asm!("wrmsr", in("ecx") msr, in("eax") low, in("edx") high);
}

/// Read 64 bits msr register.
///
/// # Safety
/// Needs CPL 0.
#[allow(unused_mut)]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let (high, low): (u32, u32);
    asm!("rdmsr", out("eax") low, out("edx") high, in("ecx") msr);
    ((high as u64) << 32) | (low as u64)
}

/// APIC Location and Status (R/W) See Table 35-2. See Section 10.4.4, Local APIC  Status and Location.
pub const IA32_APIC_BASE: u32 = 0x1b;

/// x2APIC ID register (R/O) See x2APIC Specification.
pub const IA32_X2APIC_APICID: u32 = 0x802;

/// x2APIC End of Interrupt. If ( CPUID.01H:ECX.\[bit 21\]  = 1 )
pub const IA32_X2APIC_EOI: u32 = 0x80b;

/// x2APIC Spurious Interrupt Vector register (R/W)
pub const IA32_X2APIC_SIVR: u32 = 0x80f;

/// x2APIC In-Service register bits \[31:0\] (R/O)
pub const IA32_X2APIC_ISR0: u32 = 0x810;

/// x2APIC In-Service register bits \[255:224\] (R/O)
pub const IA32_X2APIC_ISR7: u32 = 0x817;

/// x2APIC Interrupt Command register (R/W)
pub const IA32_X2APIC_ICR: u32 = 0x830;

/// If ( CPUID.01H:ECX.\[bit 21\]  = 1 )
pub const IA32_X2APIC_SELF_IPI: u32 = 0x83f;
