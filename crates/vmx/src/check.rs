//! Software implementation of VMX hardware checks
//!
//! This module implements **some** of the checks done by the VMX extension on VM entries, it is
//! intended as a tool for development and debugging.

use core::mem;

use super::bitmaps::{EntryControls, ExitControls, PinbasedControls};
use super::errors::{VmxError, VmxFieldError};
use super::msr;
use crate::fields::VmcsField;

// ———————————————————————— Main Checking Functions ————————————————————————— //

/// Check that the current VMCS is in a valid state, such that VMLAUNCH or VMRESUME can
/// successfully complete.
///
/// WARNING: the checks are not (yet) complete!
pub fn check() -> Result<(), VmxError> {
    check_exec_ctrl_fields()?;
    check_host_state()?;
    check_guest_state()?;

    Ok(())
}

/// Performs some of the checks on execution control fields (section 26.2.1).
fn check_exec_ctrl_fields() -> Result<(), VmxError> {
    // TODO: check ctrls against VMX capabilities
    let pin_ctrls = unsafe { VmcsField::PinBasedVmExecControl.vmread()? } as u32;
    let exit_ctrls = unsafe { VmcsField::VmExitControls.vmread()? } as u32;
    let entry_ctrls = unsafe { VmcsField::VmEntryControls.vmread()? } as u32;

    let pin_ctrls = PinbasedControls::from_bits_truncate(pin_ctrls);
    let exit_ctrls = ExitControls::from_bits_truncate(exit_ctrls);
    let entry_ctrls = EntryControls::from_bits_truncate(entry_ctrls);

    // TODO: execution control fields, section 26.2.1.1

    // VM-Exit Control Fields, section 26.2.1.2
    if !pin_ctrls.contains(PinbasedControls::VMX_PREEMPTION_TIMER) {
        if exit_ctrls.contains(ExitControls::SAVE_VMX_PREEMPTION_TIMER) {
            return Err(VmxError::Disallowed1(VmxFieldError::ExitControls, 22));
        }
    }
    let msr_store_count = unsafe { VmcsField::VmExitMsrStoreCount.vmread()? } as u32;
    if msr_store_count != 0 {
        let msr_store_addr = unsafe { VmcsField::VmExitMsrStoreAddr.vmread()? } as u64;
        if msr_store_addr & 0b1111 != 0 {
            return Err(VmxError::Disallowed1(
                VmxFieldError::VmExitMsrStoreAddr,
                (msr_store_addr & 0b1111).trailing_zeros() as u8,
            ));
        }
    }
    let msr_load_count = unsafe { VmcsField::VmExitMsrLoadCount.vmread()? } as u32;
    if msr_load_count != 0 {
        let msr_load_addr = unsafe { VmcsField::VmExitMsrLoadAddr.vmread()? } as u64;
        if msr_load_addr & 0b1111 != 0 {
            return Err(VmxError::Disallowed1(
                VmxFieldError::VmExitMsrLoadAddr,
                (msr_load_addr & 0b1111).trailing_zeros() as u8,
            ));
        }
    }

    // VM-Entry Control Fields, section 26.2.1.3
    let entry_int_info = unsafe { VmcsField::VmEntryIntrInfoField.vmread()? } as u32;
    if entry_int_info & (1 << 31) != 0 {
        // We only check reserved bits for now
        let reserved_bits = ((1 << 19) - 1) << 12;
        if entry_int_info & reserved_bits != 0 {
            return Err(VmxError::Disallowed1(
                VmxFieldError::VmEntryIntInfoField,
                (entry_int_info & reserved_bits).trailing_zeros() as u8,
            ));
        }
        if entry_int_info & (1 << 11) == 0 {
            return Err(VmxError::Disallowed0(
                VmxFieldError::VmEntryIntInfoField,
                11,
            ));
        }
    }
    let msr_load_count = unsafe { VmcsField::VmEntryMsrLoadCount.vmread()? } as u32;
    if msr_load_count != 0 {
        let msr_load_addr = unsafe { VmcsField::VmEntryMsrLoadAddr.vmread()? } as u32;
        if msr_load_addr & 0b1111 != 0 {
            return Err(VmxError::Disallowed1(
                VmxFieldError::VmEntryMsrLoadAddr,
                (msr_load_addr & 0b1111).trailing_zeros() as u8,
            ));
        }
    }
    if entry_ctrls.contains(EntryControls::ENTRY_TO_SMM) {
        return Err(VmxError::Disallowed1(VmxFieldError::EntryControls, 10));
    }
    if entry_ctrls.contains(EntryControls::DEACTIVATE_DUAL_MONITOR) {
        return Err(VmxError::Disallowed1(VmxFieldError::EntryControls, 11));
    }
    Ok(())
}

/// Performs some of the checks on host state fields (section 26.2.2).
fn check_host_state() -> Result<(), VmxError> {
    // Check on Host Control Registers and MSRs (section 26.2.2)
    let host_cr0 = unsafe { VmcsField::HostCr0.vmread()? };
    let host_cr4 = unsafe { VmcsField::HostCr4.vmread()? };
    validate_cr0(host_cr0).map_err(|err| err.set_field(VmxFieldError::HostCr0))?;
    validate_cr4(host_cr4).map_err(|err| err.set_field(VmxFieldError::HostCr4))?;

    if mem::size_of::<usize>() > 4 {
        // 64 bits architecture
        if host_cr0 >> 52 != 0 {
            let bit = ((host_cr0 >> 52) << 52).trailing_zeros() as u8;
            return Err(VmxError::Disallowed1(VmxFieldError::HostCr0, bit));
        }
    }

    let exit_ctrls = unsafe { VmcsField::VmExitControls.vmread()? } as u32;
    let exit_ctrls = ExitControls::from_bits_truncate(exit_ctrls);
    if exit_ctrls.contains(ExitControls::LOAD_IA32_PERF_GLOBAL_CTRL) {
        // See section 18.2.2 (Performance Monitoring)
        let reserved_bits = !((1 << 0) | (1 << 1) | (1 << 32) | (1 << 33) | (1 << 34));
        let perf_global_ctrl = unsafe { msr::IA32_PERF_GLOBAL_CTRL.read() };
        if perf_global_ctrl & reserved_bits != 0 {
            return Err(VmxError::Disallowed1(VmxFieldError::ExitControls, 12));
        }
    }
    if exit_ctrls.contains(ExitControls::LOAD_IA32_PAT) {
        // TODO
    }
    if exit_ctrls.contains(ExitControls::LOAD_IA32_EFER) {
        let reserved_bits = !((1 << 0) | (1 << 8) | (1 << 10) | (1 << 11));
        let efer = unsafe { msr::IA32_EFER.read() };
        if efer & reserved_bits != 0 {
            return Err(VmxError::Disallowed1(VmxFieldError::ExitControls, 21));
        }
        let lme = efer & (1 << 8) != 0;
        let lma = efer & (1 << 10) != 0;
        let address_space_size = exit_ctrls.contains(ExitControls::HOST_ADDRESS_SPACE_SIZE);
        if address_space_size {
            if !lma || !lme {
                return Err(VmxError::MisconfiguredBit(VmxFieldError::ExitControls, 9));
            }
        } else {
            if lma || lme {
                return Err(VmxError::MisconfiguredBit(VmxFieldError::ExitControls, 9));
            }
        }
    }

    // Checks on Host Segment and Descriptor-Table Registers
    let cs = unsafe { VmcsField::HostCsSelector.vmread()? } as u16;
    let ds = unsafe { VmcsField::HostDsSelector.vmread()? } as u16;
    let es = unsafe { VmcsField::HostEsSelector.vmread()? } as u16;
    let fs = unsafe { VmcsField::HostFsSelector.vmread()? } as u16;
    let gs = unsafe { VmcsField::HostGsSelector.vmread()? } as u16;
    let ss = unsafe { VmcsField::HostSsSelector.vmread()? } as u16;
    let tr = unsafe { VmcsField::HostTrSelector.vmread()? } as u16;
    validate_host_selector(cs).map_err(|err| err.set_field(VmxFieldError::HostCsSelector))?;
    validate_host_selector(ds).map_err(|err| err.set_field(VmxFieldError::HostDsSelector))?;
    validate_host_selector(es).map_err(|err| err.set_field(VmxFieldError::HostEsSelector))?;
    validate_host_selector(fs).map_err(|err| err.set_field(VmxFieldError::HostFsSelector))?;
    validate_host_selector(gs).map_err(|err| err.set_field(VmxFieldError::HostGsSelector))?;
    validate_host_selector(ss).map_err(|err| err.set_field(VmxFieldError::HostSsSelector))?;
    validate_host_selector(tr).map_err(|err| err.set_field(VmxFieldError::HostTrSelector))?;

    if cs == 0x0000 {
        return Err(VmxError::Misconfigured(VmxFieldError::HostCsSelector));
    }
    if tr == 0x0000 {
        return Err(VmxError::Misconfigured(VmxFieldError::HostTrSelector));
    }

    Ok(())
}

/// Performs some of the checks on guest state fields (section 26.2.3).
fn check_guest_state() -> Result<(), VmxError> {
    let guest_cr0 = unsafe { VmcsField::GuestCr0.vmread()? } as usize;
    validate_cr0(guest_cr0).map_err(|err| err.set_field(VmxFieldError::GuestCr0))?;
    let guest_cr4 = unsafe { VmcsField::GuestCr4.vmread()? } as usize;
    validate_cr4(guest_cr4).map_err(|err| err.set_field(VmxFieldError::GuestCr4))?;

    // If CR0.PG == 1, then CR0.PE must be 1
    if (guest_cr0 & (1 << 31)) != 0 {
        if (guest_cr0 & 1) != 1 {
            return Err(VmxError::Disallowed0(VmxFieldError::GuestCr0, 0));
        }
    }

    let ctrls = unsafe { VmcsField::VmEntryControls.vmread()? } as u32;
    let entry_cntrls = EntryControls::from_bits_truncate(ctrls);
    if entry_cntrls.contains(EntryControls::IA32E_MODE_GUEST) {
        if guest_cr0 & (1 << 31) == 0 {
            return Err(VmxError::Disallowed0(VmxFieldError::GuestCr0, 31));
        }
        if guest_cr4 & (1 << 5) == 0 {
            return Err(VmxError::Disallowed0(VmxFieldError::GuestCr4, 5));
        }
    } else {
        if guest_cr4 & (1 << 17) != 0 {
            return Err(VmxError::Disallowed1(VmxFieldError::GuestCr4, 17));
        }
    }

    let tr = unsafe { VmcsField::GuestTrSelector.vmread()? } as u16;
    let ss = unsafe { VmcsField::GuestSsSelector.vmread()? } as u16;
    let cs = unsafe { VmcsField::GuestCsSelector.vmread()? } as u16;
    if tr & (1 << 2) != 0 {
        return Err(VmxError::Disallowed1(VmxFieldError::GuestTrSelector, 2));
    }
    if (ss & 0b01) != (cs & 0b01) {
        return Err(VmxError::MisconfiguredBit(
            VmxFieldError::GuestSsSelector,
            0,
        ));
    }
    if (ss & 0b10) != (cs & 0b10) {
        return Err(VmxError::MisconfiguredBit(
            VmxFieldError::GuestSsSelector,
            1,
        ));
    }

    let cs_ar = unsafe { VmcsField::GuestCsArBytes.vmread()? } as u32;
    let ss_ar = unsafe { VmcsField::GuestSsArBytes.vmread()? } as u32;
    let ds_ar = unsafe { VmcsField::GuestDsArBytes.vmread()? } as u32;
    let es_ar = unsafe { VmcsField::GuestEsArBytes.vmread()? } as u32;
    let fs_ar = unsafe { VmcsField::GuestFsArBytes.vmread()? } as u32;
    let gs_ar = unsafe { VmcsField::GuestGsArBytes.vmread()? } as u32;
    let tr_ar = unsafe { VmcsField::GuestTrArBytes.vmread()? } as u32;
    let ldtr_ar = unsafe { VmcsField::GuestLdtrArBytes.vmread()? } as u32;
    let tr_limit = unsafe { VmcsField::GuestTrLimit.vmread()? } as u32;
    let gdtr_limit = unsafe { VmcsField::GuestGdtrLimit.vmread()? } as u32;
    let idtr_limit = unsafe { VmcsField::GuestIdtrLimit.vmread()? } as u32;
    let rflags = unsafe { VmcsField::GuestRflags.vmread()? };

    let cs_type = cs_ar & 0b1111;
    let ss_type = ss_ar & 0b1111;
    const UNUSABLE_MASK: u32 = 1 << 16;
    if cs_type != 9 && cs_type != 11 && cs_type != 13 && cs_type != 15 {
        // We assume "unrestricted guest" is set to 0
        return Err(VmxError::Misconfigured(VmxFieldError::GuestCsAccessRights));
    }
    if ss_ar & UNUSABLE_MASK == 0 && ss_type != 3 && ss_type != 7 {
        return Err(VmxError::Misconfigured(VmxFieldError::GuestSsAccessRights));
    }
    let check_segment_ar = |ar: u32, field: VmxFieldError| {
        if ar & UNUSABLE_MASK == 0 {
            if ar & 0b1 != 1 {
                return Err(VmxError::Disallowed0(field, 0));
            }
            if (ar & 0b1000 != 0) && (ar & 0b0010 == 0) {
                return Err(VmxError::MisconfiguredBit(field, 1));
            }
        }
        Ok(())
    };
    check_segment_ar(ds_ar, VmxFieldError::GuestDsAccessRights)?;
    check_segment_ar(es_ar, VmxFieldError::GuestEsAccessRights)?;
    check_segment_ar(fs_ar, VmxFieldError::GuestFsAccessRights)?;
    check_segment_ar(gs_ar, VmxFieldError::GuestGsAccessRights)?;
    if (cs_ar & UNUSABLE_MASK == 0) && (cs_ar & (1 << 4) == 0) {
        return Err(VmxError::Disallowed0(VmxFieldError::GuestCsAccessRights, 4));
    }
    if (tr_ar & 0b1111) != 11 {
        return Err(VmxError::Misconfigured(VmxFieldError::GuestTrAccessRights));
    }
    if (tr_ar & (1 << 4)) != 0 {
        return Err(VmxError::Disallowed1(VmxFieldError::GuestTrAccessRights, 4));
    }
    if (tr_ar & (1 << 7)) == 0 {
        return Err(VmxError::Disallowed0(VmxFieldError::GuestTrAccessRights, 7));
    }
    if (tr_ar & ((1 << 8) | (1 << 9) | (1 << 10) | (1 << 11))) != 0 {
        return Err(VmxError::Misconfigured(VmxFieldError::GuestTrAccessRights));
    }
    if ((tr_limit & 0b111111111111) != 0b111111111111) && (tr_ar & (1 << 15) != 0) {
        return Err(VmxError::MisconfiguredBit(
            VmxFieldError::GuestTrAccessRights,
            15,
        ));
    }
    if ((tr_limit & 0b11111111111100000000000000000000) != 0) && (tr & (1 << 15) == 0) {
        return Err(VmxError::MisconfiguredBit(
            VmxFieldError::GuestTrAccessRights,
            15,
        ));
    }
    if (tr_ar & UNUSABLE_MASK) != 0 {
        return Err(VmxError::Disallowed1(
            VmxFieldError::GuestTrAccessRights,
            16,
        ));
    }
    if (tr_ar >> 16) != 0 {
        return Err(VmxError::Misconfigured(VmxFieldError::GuestTrAccessRights));
    }
    if (ldtr_ar & UNUSABLE_MASK) == 0 {
        todo!();
    }
    if (gdtr_limit >> 16) != 0 {
        return Err(VmxError::Misconfigured(VmxFieldError::GuestGdtrLimit));
    }
    if (idtr_limit >> 16) != 0 {
        return Err(VmxError::Misconfigured(VmxFieldError::GuestIdtrLimit));
    }
    if (rflags >> 22) != 0 {
        return Err(VmxError::Misconfigured(VmxFieldError::GuestRflags));
    }
    if (rflags & (1 << 15)) != 0 {
        return Err(VmxError::Disallowed1(VmxFieldError::GuestRflags, 15));
    }
    if (rflags & (1 << 5)) != 0 {
        return Err(VmxError::Disallowed1(VmxFieldError::GuestRflags, 5));
    }
    if (rflags & (1 << 3)) != 0 {
        return Err(VmxError::Disallowed1(VmxFieldError::GuestRflags, 3));
    }
    if (rflags & (1 << 1)) == 0 {
        return Err(VmxError::Disallowed0(VmxFieldError::GuestRflags, 1));
    }

    Ok(())
}

// ———————————————————————————— Helper Functions ———————————————————————————— //

fn validate_host_selector(selector: u16) -> Result<(), VmxError> {
    if selector & 0b111 != 0 {
        Err(VmxError::Disallowed1(
            VmxFieldError::Unknown,
            selector.trailing_zeros() as u8,
        ))
    } else {
        Ok(())
    }
}

/// Validates CR0 register.
fn validate_cr0(cr0: usize) -> Result<(), VmxError> {
    let fixed_0 = unsafe { msr::VMX_CR0_FIXED0.read() } as usize;
    let fixed_1 = unsafe { msr::VMX_CR0_FIXED1.read() } as usize;
    validate_cr(cr0, fixed_0, fixed_1)
}

/// Validates CR4 register.
fn validate_cr4(cr4: usize) -> Result<(), VmxError> {
    let fixed_0 = unsafe { msr::VMX_CR4_FIXED0.read() } as usize;
    let fixed_1 = unsafe { msr::VMX_CR4_FIXED1.read() } as usize;
    validate_cr(cr4, fixed_0, fixed_1)
}

/// Validates a control register (CR0 or CR4) against its valid state.
///
/// See Intel Manual volume 3 annex A.7 & A.8.
fn validate_cr(cr: usize, fixed_0: usize, fixed_1: usize) -> Result<(), VmxError> {
    let must_be_zero = fixed_0 & !cr;
    if must_be_zero != 0 {
        let idx = must_be_zero.trailing_zeros() as u8;
        return Err(VmxError::Disallowed0(VmxFieldError::Unknown, idx));
    }

    let must_be_zero = (!fixed_1) & cr;
    if must_be_zero != 0 {
        let idx = must_be_zero.trailing_zeros() as u8;
        return Err(VmxError::Disallowed1(VmxFieldError::Unknown, idx));
    }

    Ok(())
}

// ————————————————————————————————— Tests —————————————————————————————————— //

#[cfg(test)]
mod test {
    use super::*;

    /// See manual Annex A.7 & A.8
    #[rustfmt::skip]
    #[test]
    fn validate_cr() {
        // Testing valid combinations
        let fixed_0: usize = 0b001_000;
        let fixed_1: usize = 0b111_011;
        let cr:      usize = 0b011_010;

        assert_eq!(super::validate_cr(cr, fixed_0, fixed_1), Ok(()));

        // testing disallowed one
        let fixed_0: usize = 0b0_001;
        let fixed_1: usize = 0b0_111;
        let cr:      usize = 0b1_011;

        assert_eq!(
            super::validate_cr(cr, fixed_0, fixed_1),
            Err(VmxError::Disallowed1(VmxFieldError::Unknown, 3))
        );

        // testing disallowed one
        let fixed_0: usize = 0b1_01;
        let fixed_1: usize = 0b1_11;
        let cr:      usize = 0b0_11;

        assert_eq!(
            super::validate_cr(cr, fixed_0, fixed_1),
            Err(VmxError::Disallowed0(VmxFieldError::Unknown, 2))
        );
    }
}
