#![no_std]

mod msr;

use core::iter::Iterator;

use bit_field::BitField;

use crate::msr::*;

// An x2apic implementation
pub struct X2Apic {
    base: u64,
}

impl X2Apic {
    pub fn new() -> Self {
        // Read the Local APIC Base Address
        let mut apic_base = unsafe { rdmsr(IA32_APIC_BASE) };

        unsafe {
            // Enable Local APIC in X2APIC mode
            // 1. Enable LAPIC in XAPIC mode
            apic_base.set_bit(10, true);
            wrmsr(IA32_APIC_BASE, apic_base);
            // 2. Enable LAPIC in X2APIC mode
            apic_base.set_bit(11, true);
            wrmsr(IA32_APIC_BASE, apic_base);
        }

        Self { base: apic_base }
    }

    pub fn init(&mut self) {
        unsafe {
            // Disable the LAPIC first by set the mask bits for all of the LVT entries
            wrmsr(IA32_X2APIC_SIVR, 0);

            // Enable this XAPIC (set bit 8, spurious IRQ vector 15)
            let svr: u64 = 1 << 8 | 15;
            wrmsr(IA32_X2APIC_SIVR, svr);

            // Clear the ISRs to ensure there are no ISR bits left
            self.clear_isr();
        }

        // TODO: The x86 crate also write to the LVT_LINT0 as the following, but I cannot find any
        // explanation on the Intel documents.
        // Also, x86 has a rdmsr on the ESR register. I cannot find proper explanation
        // let lint0 = 1 << 16 | (1 << 15) | (0b111 << 8) | 0x20;
        // wrmsr(IA32_X2APIC_LVT_LINT0, lint0);
        // let _esr = rdmsr(IA32_X2APIC_ESR);
    }

    /// Implements the second method in Intel SDM 11.4.3
    /// "Using the software enable/disable flag in the spurious-interrupt vector register"
    pub fn software_disable(&mut self) {
        // Check if the IA32_APIC_BASE[11] is 1
        //
        // Disable LAPIC by clearing the APIC software enable/disable flag in the SVR
        let svr: u64 = 0 << 8 | 15;
        unsafe { wrmsr(IA32_X2APIC_SIVR, svr) };
    }

    // Assure that the processor does not get hung up due to already set in-service interrupts left
    // over from the bootloader.
    fn clear_isr(&mut self) {
        for isr_reg in (IA32_X2APIC_ISR0..=IA32_X2APIC_ISR7).rev() {
            for _ in 0..32 {
                unsafe {
                    if rdmsr(isr_reg) != 0 {
                        wrmsr(IA32_X2APIC_EOI, 0);
                    } else {
                        break;
                    }
                }
            }
        }
    }

    pub fn send_eoi(&mut self) {
        unsafe {
            wrmsr(IA32_X2APIC_EOI, 0);
        }
    }

    pub fn send_startup_ipi(&mut self, core: u32, start_page: u8) {
        let icr: u64 = ((core as u64) << 32)
            | ((0 as u64) << 18)
            | (0x0 << 15)
            | (0x0 << 14)
            | (0x0 << 11)
            | (0x6 << 8)
            | (start_page as u64);
        unsafe { wrmsr(IA32_X2APIC_ICR, icr) };
    }

    pub fn send_init_assert(&mut self, core: u32) {
        let icr: u64 = ((core as u64) << 32)
            | (0x0 << 18)
            | (0x1 << 15)
            | (0x1 << 14)
            | (0x0 << 11)
            | (0x5 << 8);
        unsafe { wrmsr(IA32_X2APIC_ICR, icr) };
    }

    pub fn send_init_deassert(&mut self) {
        let icr: u64 = ((0x0 as u64) << 32)
            | (0x2 << 18)
            | (0x1 << 15)
            | (0x0 << 14)
            | (0x0 << 11)
            | (0x5 << 8);
        unsafe { wrmsr(IA32_X2APIC_ICR, icr) };
    }

    pub fn send_ipi(&mut self, core: u32, vector: u8) {
        // Am I sending IPI to myself?
        if pcpu_id() == core {
            unsafe { wrmsr(IA32_X2APIC_SELF_IPI, vector as u64) };
        } else {
            // TODO: The x86 crate also clears the ESR, which seems largely unnecessary based on
            // the Intel SDM, unless we want to clear the error status of the x2apic.
            // wrmsr(IA32_X2APIC_ESR, 0);
            // wrmsr(IA32_X2APIC_ESR, 0);

            // Oversimplified icr write: fixed, physical destination mode, idle delivery
            // status, level = 0, edge triggered, no shorthand
            let icr: u64 = ((core as u64) << 32) | (vector as u64) | (0 << 11);
            unsafe { wrmsr(IA32_X2APIC_ICR, icr) };
        }
    }

    pub fn bsp(&self) -> bool {
        (self.base & (1 << 8)) > 0
    }

    pub fn id(&self) -> u32 {
        unsafe { rdmsr(IA32_X2APIC_APICID) as u32 }
    }
}

pub fn pcpu_id() -> u32 {
    let cpuid = unsafe { core::arch::x86_64::__cpuid(0x01) };
    ((cpuid.ebx & 0xffffffff) >> 24) as u32
}

// temporarily expose this function to the second stage, as we're not supposed to reinitialize apic
// after linux td0 takes over
pub fn send_init_assert(core: u32) {
    let icr: u64 =
        ((core as u64) << 32) | (0x0 << 18) | (0x1 << 15) | (0x1 << 14) | (0x0 << 11) | (0x5 << 8);
    unsafe { wrmsr(IA32_X2APIC_ICR, icr) };
}
pub fn send_eoi() {
    unsafe {
        wrmsr(IA32_X2APIC_EOI, 0);
    }
}
