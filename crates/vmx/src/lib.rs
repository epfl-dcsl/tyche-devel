//! VMX support
//!
//! Inspired and in part copied from the [x86] crate.
//!
//! [x86]: https://hermitcore.github.io/libhermit-rs/x86/bits64/vmx/index.html
#![cfg_attr(not(test), no_std)]

pub mod bitmaps;
pub mod check;
pub mod ept;
pub mod errors;
pub mod fields;
pub mod msr;
pub mod raw;

use core::arch;
use core::arch::asm;
use core::marker::PhantomData;
use core::ptr::NonNull;

use bitmaps::{
    exit_qualification, EntryControls, ExceptionBitmap, ExitControls, PinbasedControls,
    PrimaryControls, SecondaryControls,
};
use fields::traits::*;
pub use utils::{Frame, GuestPhysAddr, GuestVirtAddr, HostPhysAddr, HostVirtAddr};

pub use crate::errors::{
    InterruptionType, VmExitInterrupt, VmxError, VmxExitReason, VmxFieldError,
};

/// Mask for keeping only the 32 lower bits.
const LOW_32_BITS_MASK: u64 = (1 << 32) - 1;

/// CPUID mask for VMX support
const CPUID_ECX_VMX_MASK: u32 = 1 << 5;

/// CPUID mask for INVPCID support
pub const CPUID_EBX_X64_FEATURE_INVPCID: u32 = 1 << 10;

// ————————————————————————————— VMX Operations ————————————————————————————— //

/// Basic VMX Information.
///
/// See Intel SDM Vol. 3D Appendix A-1.
#[derive(Clone, Debug)]
pub struct VmxBasicInfo {
    /// The 31-bits VMCS revision identifier used by the CPU.
    pub revision: u32,

    /// Minimum required size in bytes for VMCS and VMXON regions.
    pub vmcs_width: u32,

    /// Support the VMX_TRUE_CTLS registers.
    pub support_true_ctls: bool,
    // TODO: list supported memory types.
}

/// Returns Ok is VMX is available, otherwise returns the reason it's not.
///
/// If VMX is available but not enabled, the configuration registers are updated properly to enable
/// it.
pub fn vmx_available() -> Result<(), VmxError> {
    const VIRTUAL_MACHINE_EXTENSION: u64 = 1 << 13;

    // SAFETY: the CPUID instruction is not supported under SGX, we assume that this function is
    // never executed under SGX.
    let cpuid = unsafe { arch::x86_64::__cpuid(0x01) };
    if (cpuid.ecx & CPUID_ECX_VMX_MASK) == 0 {
        return Err(VmxError::VmxNotSupported);
    }

    // Enable VMX if available but not configured.
    let cr4 = read_cr4();
    if (cr4 & VIRTUAL_MACHINE_EXTENSION) == 0 {
        // SAFETY: it is always (really?) possible to set the VMX bit, but removing it during VMX
        // operation causes #UD.
        unsafe {
            write_cr4(cr4 | VIRTUAL_MACHINE_EXTENSION);
        }
    }

    // See manual 3C Section 23.7
    let feature_control = unsafe { msr::FEATURE_CONTROL.read() };
    if feature_control & 0b110 == 0 || feature_control & &0b001 == 0 {
        return Err(VmxError::VmxNotSupported);
    }

    Ok(())
}

pub fn secondary_controls_capabilities() -> Result<bitmaps::SecondaryControls, VmxError> {
    // Check that VMX is available
    vmx_available()?;

    // SAFETY: MSR exists if vmx is available.
    let procbased_ctls = unsafe { msr::VMX_PROCBASED_CTLS.read() };
    if procbased_ctls & (1 << 63) == 0 {
        return Err(VmxError::FeatureNotSupported);
    }

    // SAFETY: MSR exists if bit 63 of procbased_ctls is 1.
    let second_procbased_ctrl = unsafe { msr::VMX_PROCBASED_CTLS2.read() };
    let allowed_1 = (second_procbased_ctrl >> 32) as u32;
    Ok(bitmaps::SecondaryControls::from_bits_truncate(allowed_1))
}

/// Return the EPT and VPID capabilities.
///
/// See Intel manual volume 3 annex A.10.
pub fn ept_capabilities() -> Result<bitmaps::EptCapability, VmxError> {
    // Check that VMX is available
    vmx_available()?;

    // SAFETY: MSR exists if vmx is available.
    let procbased_ctls = unsafe { msr::VMX_PROCBASED_CTLS.read() };
    if procbased_ctls & (1 << 63) == 0 {
        return Err(VmxError::FeatureNotSupported);
    }

    // SAFETY: MSR exists if bit 63 of procbased_ctls is 1.
    let second_procbased_ctrl = unsafe { msr::VMX_PROCBASED_CTLS2.read() };
    if second_procbased_ctrl & (1 << 33) == 0 {
        return Err(VmxError::FeatureNotSupported);
    }

    // SAFETY: MSR exists if bit 33 of second_procbased_ctrl is 1.
    let capabilities = unsafe { msr::VMX_EPT_VPID_CAP.read() };
    Ok(bitmaps::EptCapability::from_bits_truncate(capabilities))
}

/// Return available VM functions.
///
/// See Intel manual volume 3 section 24.6.14.
pub fn available_vmfuncs() -> Result<bitmaps::VmFuncControls, VmxError> {
    // SAFETY: MSR exists if vmx is available.
    let procbased_ctls = unsafe { msr::VMX_PROCBASED_CTLS.read() };
    if procbased_ctls & (1 << 63) == 0 {
        return Err(VmxError::FeatureNotSupported);
    }

    // SAFETY: MSR exists if bit 63 of procbased_ctls is 1.
    let second_procbased_ctrl = unsafe { msr::VMX_PROCBASED_CTLS2.read() };
    if second_procbased_ctrl & (1 << 45) == 0 {
        return Err(VmxError::FeatureNotSupported);
    }

    // SAFETY: MSR exists if bit 45 of second_procbased_ctrl is 1.
    let capabilities = unsafe { msr::VMX_VMFUNC.read() };
    Ok(bitmaps::VmFuncControls::from_bits_truncate(capabilities))
}

/// Return basic info about VMX CPU-defined structures.
///
/// SAFETY: This function assumes that VMX is available, otherwise its behavior is undefined.
unsafe fn get_vmx_info() -> VmxBasicInfo {
    // SAFETY: this register can be read if VMX is available.
    let raw_info = msr::VMX_BASIC.read();
    let revision = raw_info & ((1 << 32) - 1); // bits 31:0
    let revision = revision as u32;
    let vmcs_width = (raw_info & ((1 << 45) - 1)) >> 32; // bits 44:32
    let vmcs_width = vmcs_width as u32;
    let support_true_ctls = raw_info & (1 << 55) != 0;
    VmxBasicInfo {
        revision,
        vmcs_width,
        support_true_ctls,
    }
}

// ————————————————————————————————— VMXON —————————————————————————————————— //

pub struct Vmxon {
    frame: Frame,
    // This fiels makes Vmxon !Sync and !Send, therefore it can't be send or shared with another
    // core.
    _not_sync: PhantomData<*const ()>,
}

/// Enter VMX operations.
///
/// SAFETY: This function assumes that VMX is available, otherwise its behavior is unefined.
//  NOTE: see Intel SDM Vol 3C Section 24.11.5
pub unsafe fn vmxon(mut frame: Frame) -> Result<Vmxon, VmxError> {
    let vmcs_info = get_vmx_info();

    // Initialize the VMXON region by copying the revision ID into the 4 first bytes of VMXON
    // region
    frame.zero_out();
    frame.as_mut()[0..4].copy_from_slice(&vmcs_info.revision.to_le_bytes());
    raw::vmxon(frame.phys_addr.as_u64())?;
    Ok(Vmxon {
        frame,
        _not_sync: PhantomData,
    })
}

impl Vmxon {
    /// Turns off VMX mode.
    pub unsafe fn vmxoff(self) -> Result<Frame, VmxError> {
        let frame = self.frame;
        raw::vmxoff()?;
        Ok(frame)
    }

    /// Creates a new VM control structure from the given frame.
    pub unsafe fn create_vm(&self, frame: Frame) -> Result<VmcsRegion, VmxError> {
        self.create_vm_unsafe(frame)
    }

    /// Creates a new VM control structure from the given frame.
    ///
    /// This version returns a VmcsRegion that is not bound to Vmxon, which means that the caller
    /// has to ensure Vmxon outlives the resulting VmcsRegion.
    pub unsafe fn create_vm_unsafe(
        &self,
        mut frame: Frame,
    ) -> Result<VmcsRegion<'static>, VmxError> {
        let vmcs_info = get_vmx_info();

        // Initialize the VMCS region by copying the revision ID into the 4 first bytes of VMCS
        // region
        frame.zero_out();
        frame.as_mut()[0..4].copy_from_slice(&vmcs_info.revision.to_le_bytes());

        // Use VMCLEAR to put the VMCS in a clear (valid) state.
        raw::vmclear(frame.phys_addr.as_u64())?;

        Ok(VmcsRegion {
            frame,
            regs: [0; 15],
            msr_bitmaps: None,
            _lifetime: PhantomData,
            _not_sync: PhantomData,
        })
    }
}

// —————————————————————————————————— VMCS —————————————————————————————————— //

/// A region containing information about a VM.
pub struct VmcsRegion<'vmx> {
    // Set of registers to save/restore
    regs: [u64; REGFILE_SIZE],
    /// The frame used by the region.
    frame: Frame,
    /// The MSR read and write bitmaps.
    msr_bitmaps: Option<NonNull<msr::MsrBitmaps>>,
    /// This fields creates an artificial lifetime for the region.
    _lifetime: PhantomData<&'vmx ()>,
    /// This fiels makes VmcsRegion !Sync and !Send, therefore it can't be send or shared with
    /// another core.
    _not_sync: PhantomData<*const ()>,
}

/// The active Vmcs. Writting to vmcs using assembly or raw wrappers will write to this structures.
pub struct ActiveVmcs<'vmx> {
    region: VmcsRegion<'vmx>,
}

impl<'vmx> VmcsRegion<'vmx> {
    /// Makes this region the current active region.
    //  TODO: Enforce that only a single region can be active at any time.
    pub fn set_as_active(self: Self) -> Result<ActiveVmcs<'vmx>, VmxError> {
        unsafe { raw::vmptrld(self.frame.phys_addr.as_u64())? };
        Ok(ActiveVmcs { region: self })
    }
}

impl<'vmx> ActiveVmcs<'vmx> {
    /// Deactivates the region.
    pub fn deactivate(self) -> Result<VmcsRegion<'vmx>, VmxError> {
        unsafe { raw::vmclear(self.region.frame.phys_addr.as_u64())? };
        Ok(self.region)
    }

    /// Returns a given register.
    pub fn get(&self, register: Register) -> u64 {
        match register {
            // SAFETY: We know that these registers always exits and that there is an active VMCS.
            Register::Rsp => unsafe { fields::GuestStateNat::Rsp.vmread().unwrap() as u64 },
            Register::Rip => unsafe { fields::GuestStateNat::Rip.vmread().unwrap() as u64 },
            _ => self.region.regs[register as usize],
        }
    }

    ///s Set a given register.
    pub fn set(&mut self, register: Register, value: u64) {
        match register {
            // SAFETY: We know that these registers always exits and that there is an active VMCS.
            Register::Rsp => unsafe { fields::GuestStateNat::Rsp.vmwrite(value as usize).unwrap() },
            Register::Rip => unsafe { fields::GuestStateNat::Rip.vmwrite(value as usize).unwrap() },
            _ => self.region.regs[register as usize] = value,
        };
    }

    /// Sets a given control register.
    pub fn set_cr(&mut self, register: ControlRegister, value: usize) {
        // SAFETY: all the fields exists on all architecture, except Cr8 which is only available on
        // x86_64.
        unsafe {
            match register {
                ControlRegister::Cr0 => fields::GuestStateNat::Cr0.vmwrite(value),
                ControlRegister::Cr3 => fields::GuestStateNat::Cr3.vmwrite(value),
                ControlRegister::Cr4 => fields::GuestStateNat::Cr4.vmwrite(value),
                ControlRegister::Cr8 => todo!("Handle Cr8"),
            }
        }
        .unwrap();
    }

    /// Returns a given control register.
    pub fn get_cr(&self, register: ControlRegister) -> usize {
        // SAFETY: all the fields exists on all architecture, except Cr8 which is only available on
        // x86_64.
        unsafe {
            match register {
                ControlRegister::Cr0 => fields::GuestStateNat::Cr0.vmread(),
                ControlRegister::Cr3 => fields::GuestStateNat::Cr3.vmread(),
                ControlRegister::Cr4 => fields::GuestStateNat::Cr4.vmread(),
                ControlRegister::Cr8 => todo!("Handle Cr8"),
            }
        }
        .unwrap()
    }

    pub fn set16(&mut self, field: fields::GuestState16, value: u16) -> Result<(), VmxError> {
        unsafe { field.vmwrite(value) }
    }

    pub fn get16(&self, field: fields::GuestState16) -> Result<u16, VmxError> {
        unsafe { field.vmread() }
    }

    pub fn set32(&mut self, field: fields::GuestState32, value: u32) -> Result<(), VmxError> {
        unsafe { field.vmwrite(value) }
    }

    pub fn get32(&self, field: fields::GuestState32) -> Result<u32, VmxError> {
        unsafe { field.vmread() }
    }

    pub fn set64(&mut self, field: fields::GuestState64, value: u64) -> Result<(), VmxError> {
        unsafe { field.vmwrite(value) }
    }

    pub fn get64(&self, field: fields::GuestState64) -> Result<u64, VmxError> {
        unsafe { field.vmread() }
    }

    pub fn set_nat(&mut self, field: fields::GuestStateNat, value: usize) -> Result<(), VmxError> {
        unsafe { field.vmwrite(value) }
    }

    pub fn get_nat(&self, field: fields::GuestStateNat) -> Result<usize, VmxError> {
        unsafe { field.vmread() }
    }

    pub fn get_ctrlnat(&self, field: fields::CtrlNat) -> Result<usize, VmxError> {
        unsafe { field.vmread() }
    }

    /// Set guest RIP to the next instruction.
    ///
    /// This function must be called at most once between two VM exits, as the instruction
    /// lenght is not updated until VM exits again.
    pub fn next_instruction(&mut self) -> Result<(), VmxError> {
        // TODO: Chech that instr-len is availlable on all CPU, remove Result if that's the case.
        let instr_len = unsafe { fields::GuestState32Ro::VmExitInstructionLenght.vmread()? as u64 };
        let rip = self.get(Register::Rip);
        Ok(self.set(Register::Rip, rip + instr_len))
    }

    /// Returns the exit reason.
    pub fn exit_reason(&self) -> Result<VmxExitReason, VmxError> {
        let reason = unsafe { fields::GuestState32Ro::ExitReason.vmread() }?;
        Ok(VmxExitReason::from_u16((reason & 0xFFFF) as u16))
    }

    /// Returns the exit qualification.
    pub fn exit_qualification(&self) -> Result<VmxExitQualification, VmxError> {
        let qualification = unsafe { fields::GuestStateNatRo::ExitQualification.vmread() }?;
        Ok(VmxExitQualification { raw: qualification })
    }

    /// Returns the guest physical address.
    ///
    /// This field is set on VM exits due to EPT violations and EPT misconfigurations.
    /// See section 27.2.1 for details of when and how this field is used.
    pub fn guest_phys_addr(&self) -> Result<GuestPhysAddr, VmxError> {
        let guest_phys_addr = unsafe { fields::GuestState64Ro::GuestPhysAddr.vmread() }?;
        Ok(GuestPhysAddr::new(guest_phys_addr as usize))
    }

    /// Returns the guest virtual address.
    ///
    /// This field is set for some VM exits. See section 27.2.1 for details of when and how this
    /// field is used.
    pub fn guest_linear_addr(&self) -> Result<GuestVirtAddr, VmxError> {
        let guest_virt_addr = unsafe { fields::GuestStateNatRo::GuestLinearAddr.vmread() }?;
        Ok(GuestVirtAddr::new(guest_virt_addr))
    }

    pub fn interrupt_info(&self) -> Result<Option<VmExitInterrupt>, VmxError> {
        let info = unsafe { fields::GuestState32Ro::VmExitInterruptInfo.vmread()? };
        if (info & (1 << 31)) == 0 {
            return Ok(None);
        }

        let vector = (info & 0xFF) as u8;
        let int_type = InterruptionType::from_raw(info);
        let error_code = if (info & (1 << 11)) != 0 {
            Some(unsafe { fields::GuestState32Ro::VmExitInterruptErrCode.vmread()? })
        } else {
            None
        };
        Ok(Some(VmExitInterrupt {
            vector,
            int_type,
            error_code,
        }))
    }

    /// Initializes the MSR bitmaps, default to deny all reads and writes.
    ///
    /// SAFETY: The frame must be valid and becomes entirely owned by the VMCS, that is any future
    /// access to the frame while the VMCS is still alive is undefined behavior.
    pub unsafe fn initialize_msr_bitmaps(
        &mut self,
        frame: Frame,
    ) -> Result<&mut msr::MsrBitmaps, VmxError> {
        debug_assert_eq!(core::mem::size_of::<msr::MsrBitmaps>(), 0x1000);
        fields::Ctrl64::MsrBitmaps.vmwrite(frame.phys_addr.as_u64())?;
        self.region.msr_bitmaps = NonNull::new(frame.virt_addr as *mut msr::MsrBitmaps);
        if let Some(mut bitmap) = self.region.msr_bitmaps {
            Ok(bitmap.as_mut())
        } else {
            Err(VmxError::Misconfigured(VmxFieldError::MsrBitmaps))
        }
    }

    /// Returns a mutable reference to the MSR bitmaps, if any.
    pub fn get_msr_bitmaps(&mut self) -> Option<&mut msr::MsrBitmaps> {
        if let Some(bitmap_ptr) = &mut self.region.msr_bitmaps {
            // SAFETY: the region has total ownership of the bitmap frame
            unsafe { Some(bitmap_ptr.as_mut()) }
        } else {
            None
        }
    }

    /// Launch the VM.
    ///
    /// SAFETY: the VMCS must be properly configured so that the host can resume execution in a
    /// sensible environment. A simple way of ensuring that is to save the current environment as
    /// host state.
    pub unsafe fn launch(&mut self) -> Result<VmxExitReason, VmxError> {
        raw::vmlaunch(self)?;
        self.exit_reason()
    }

    /// Resume the VM.
    ///
    /// SAFETY: the VMCS must be properly configured so that the host can resume execution in a
    /// sensible environment. A simple way of ensuring that is to save the current environment as
    /// host state.
    pub unsafe fn resume(&mut self) -> Result<VmxExitReason, VmxError> {
        raw::vmresume(self)?;
        self.exit_reason()
    }

    /// Sets the pin-based controls.
    pub fn set_pin_based_ctrls(&mut self, flags: PinbasedControls) -> Result<(), VmxError> {
        unsafe {
            Self::set_ctrls(
                flags.bits(),
                PinbasedControls::all().bits(),
                msr::VMX_PINBASED_CTLS,
                msr::VMX_TRUE_PINBASED_CTLS,
                fields::Ctrl32::PinBasedExecCtrls,
            )
            .map_err(|err| err.set_field(VmxFieldError::PinBasedControls))
        }
    }

    /// Returns the pin-based controls
    pub fn get_pin_based_ctrls(&self) -> Result<PinbasedControls, VmxError> {
        let ctrls = unsafe { fields::Ctrl32::PinBasedExecCtrls.vmread()? };
        Ok(PinbasedControls::from_bits_truncate(ctrls))
    }

    /// Sets the primary processor-based controls.
    pub fn set_primary_ctrls(&mut self, flags: PrimaryControls) -> Result<(), VmxError> {
        unsafe {
            Self::set_ctrls(
                flags.bits(),
                PrimaryControls::all().bits(),
                msr::VMX_PROCBASED_CTLS,
                msr::VMX_TRUE_PROCBASED_CTLS,
                fields::Ctrl32::PrimaryProcBasedExecCtrls,
            )
            .map_err(|err| err.set_field(VmxFieldError::PrimaryControls))
        }
    }

    /// Returns the primary processor-based controls.
    pub fn get_primary_ctrls(&self) -> Result<PrimaryControls, VmxError> {
        let ctrls = unsafe { fields::Ctrl32::PrimaryProcBasedExecCtrls.vmread()? };
        Ok(PrimaryControls::from_bits_truncate(ctrls))
    }

    /// Sets the secondary processor-based controls.
    pub fn set_secondary_ctrls(&mut self, flags: SecondaryControls) -> Result<(), VmxError> {
        unsafe {
            let spec = msr::VMX_PROCBASED_CTLS2.read();
            let new_flags = Self::get_ctls(flags.bits(), spec, SecondaryControls::all().bits())
                .map_err(|err| err.set_field(VmxFieldError::SecondaryControls))?;
            fields::Ctrl32::SecondaryProcBasedVmExecCtrls.vmwrite(new_flags)
        }
    }

    /// Returns the secondary processor-based controls.
    pub fn get_secondary_ctrls(&self) -> Result<SecondaryControls, VmxError> {
        let ctrls = unsafe { fields::Ctrl32::SecondaryProcBasedVmExecCtrls.vmread()? };
        Ok(SecondaryControls::from_bits_truncate(ctrls))
    }

    /// Sets the VM exit controls.
    pub fn set_vm_exit_ctrls(&mut self, flags: ExitControls) -> Result<(), VmxError> {
        unsafe {
            Self::set_ctrls(
                flags.bits(),
                ExitControls::all().bits(),
                msr::VMX_EXIT_CTLS,
                msr::VMX_TRUE_EXIT_CTLS,
                fields::Ctrl32::VmExitCtrls,
            )
            .map_err(|err| err.set_field(VmxFieldError::ExitControls))
        }
    }

    /// Returns the VM exit controls
    pub fn get_vm_exit_ctrls(&self) -> Result<ExitControls, VmxError> {
        let ctrls = unsafe { fields::Ctrl32::VmExitCtrls.vmread()? };
        Ok(ExitControls::from_bits_truncate(ctrls))
    }

    /// Sets the VM entry controls.
    pub fn set_vm_entry_ctrls(&mut self, flags: EntryControls) -> Result<(), VmxError> {
        unsafe {
            Self::set_ctrls(
                flags.bits(),
                EntryControls::all().bits(),
                msr::VMX_ENTRY_CTLS,
                msr::VMX_TRUE_ENTRY_CTLS,
                fields::Ctrl32::VmEntryCtrls,
            )
            .map_err(|err| err.set_field(VmxFieldError::EntryControls))
        }
    }

    /// Returns the VM entry controls.
    pub fn get_vm_entry_cntrls(&self) -> Result<EntryControls, VmxError> {
        let ctrls = unsafe { fields::Ctrl32::VmEntryCtrls.vmread()? };
        Ok(EntryControls::from_bits_truncate(ctrls))
    }

    /// Sets the VM Entry interruption information field.
    pub fn set_vm_entry_interruption_information(&mut self, flags: u32) -> Result<(), VmxError> {
        unsafe {
            fields::Ctrl32::VmEntryIntInfoField
                .vmwrite(flags)
                .map_err(|err| err.set_field(VmxFieldError::VmEntryIntInfoField))
        }
    }

    /// Sets the Cr0 guest/host mask.
    ///
    /// Bits set to 1 will be read from the Cr0 shadow and modification attempt wills cause VM
    /// exits.
    pub fn set_cr0_mask(&mut self, cr0_mask: usize) -> Result<(), VmxError> {
        unsafe { fields::CtrlNat::Cr0Mask.vmwrite(cr0_mask) }
    }

    /// Sets the Cr4 guest/host mask.
    ///
    /// Bits set to 1 will be read from the Cr4 shadow and modification attempt wills cause VM
    /// exits.
    pub fn set_cr4_mask(&mut self, cr4_mask: usize) -> Result<(), VmxError> {
        unsafe { fields::CtrlNat::Cr4Mask.vmwrite(cr4_mask) }
    }

    /// Sets the Cr0 read shadow.
    pub fn set_cr0_shadow(&mut self, cr0_shadow: usize) -> Result<(), VmxError> {
        unsafe { fields::CtrlNat::Cr0ReadShadow.vmwrite(cr0_shadow) }
    }

    /// Sets the Cr4 read shadow.
    pub fn set_cr4_shadow(&mut self, cr4_shadow: usize) -> Result<(), VmxError> {
        unsafe { fields::CtrlNat::Cr4ReadShadow.vmwrite(cr4_shadow) }
    }

    /// Sets the exception bitmap.
    pub fn set_exception_bitmap(&mut self, bitmap: ExceptionBitmap) -> Result<(), VmxError> {
        // TODO: is there a list of allowed settings?
        unsafe { fields::Ctrl32::ExceptionBitmap.vmwrite(bitmap.bits()) }
    }
    /// Gets the exception bitmap.
    pub fn get_exception_bitmap(&self) -> Result<ExceptionBitmap, VmxError> {
        let bitmap = unsafe { fields::Ctrl32::ExceptionBitmap.vmread()? };
        Ok(ExceptionBitmap::from_bits_truncate(bitmap))
    }

    /// Sets the extended page table (EPT) pointer.
    pub fn set_ept_ptr(&mut self, ept_ptr: HostPhysAddr) -> Result<(), VmxError> {
        unsafe { fields::Ctrl64::EptPtr.vmwrite(ept_ptr.as_u64()) }
    }

    pub fn get_ept_ptr(&self) -> Result<u64, VmxError> {
        unsafe { fields::Ctrl64::EptPtr.vmread() }
    }

    /// Sets the EPTP address list.
    pub fn set_eptp_list(&mut self, eptp_list: &ept::EptpList) -> Result<(), VmxError> {
        unsafe { fields::Ctrl64::EptpListAddr.vmwrite(eptp_list.get_ptr().as_u64()) }
    }

    pub fn get_eptp_list(&self) -> Result<u64, VmxError> {
        unsafe { fields::Ctrl64::EptpListAddr.vmread() }
    }

    /// Enable the vmfunc controls.
    pub fn set_vmfunc_ctrls(&mut self, flags: bitmaps::VmFuncControls) -> Result<(), VmxError> {
        let allowed_vmfuncs = available_vmfuncs()?;
        Self::validate_flags_allowed(flags.bits(), allowed_vmfuncs.bits())
            .map_err(|err| err.set_field(VmxFieldError::VmFuncControls))?;
        unsafe { fields::Ctrl64::VmFuncCtrls.vmwrite(1) }
    }

    /// Sets a control setting for the current VMCS.
    ///
    /// Raw flags is a raw 32 bits bitflag vector, known is the birflags of bits known by the VMM,
    /// spec and true_spec MSRs are the MSRs containing the supported features of the current CPU.
    ///
    /// See Intel SDM Vol 3D Appending A.3.1 for allowed settings explanation.
    unsafe fn set_ctrls(
        raw_flags: u32,
        known: u32,
        spec_msr: msr::Msr,
        true_spec_msr: msr::Msr,
        control: fields::Ctrl32,
    ) -> Result<(), VmxError> {
        let vmx_info = get_vmx_info();
        let spec = spec_msr.read();
        let new_flags = if vmx_info.support_true_ctls {
            let true_spec = true_spec_msr.read();
            Self::get_true_ctls(raw_flags, spec, true_spec, known)?
        } else {
            Self::get_ctls(raw_flags, spec, known)?
        };

        control.vmwrite(new_flags)
    }

    /// Computes the control bits when there is no support for true controls.
    ///
    /// In case of error, returns the index of a bit
    fn get_ctls(user: u32, spec: u64, known: u32) -> Result<u32, VmxError> {
        // NOTE: see Intel SDM Vol 3C Section 31.5.1, algorithm 3
        let allowed_zeros = (spec & LOW_32_BITS_MASK) as u32;
        let allowed_ones = (spec >> 32) as u32;

        let must_be_0 = !user & allowed_zeros & known;
        if must_be_0 != 0 {
            let idx = must_be_0.trailing_zeros() as u8;
            return Err(VmxError::Disallowed0(VmxFieldError::Unknown, idx));
        }
        let must_be_0 = user & !allowed_ones & known;
        if must_be_0 != 0 {
            let idx = must_be_0.trailing_zeros() as u8;
            return Err(VmxError::Disallowed1(VmxFieldError::Unknown, idx));
        }

        let default_value = allowed_zeros & allowed_ones;
        Ok(user | default_value)
    }

    /// Computes the control bits when there  is support for true controls.
    fn get_true_ctls(user: u32, spec: u64, true_spec: u64, known: u32) -> Result<u32, VmxError> {
        // NOTE: see Intel SDM Vol 3C Section 31.5.1, algorithm 3
        let allowed_zeros = (spec & LOW_32_BITS_MASK) as u32;
        let true_allowed_zeros = (true_spec & LOW_32_BITS_MASK) as u32;
        let true_allowed_ones = (true_spec >> 32) as u32;

        let must_be_0 = !user & true_allowed_zeros & known;
        if must_be_0 != 0 {
            let idx = must_be_0.trailing_zeros() as u8;
            return Err(VmxError::Disallowed0(VmxFieldError::Unknown, idx));
        }
        let must_be_0 = user & !true_allowed_ones & known;
        if must_be_0 != 0 {
            let idx = must_be_0.trailing_zeros() as u8;
            return Err(VmxError::Disallowed1(VmxFieldError::Unknown, idx));
        }

        let default_value = true_allowed_zeros & true_allowed_ones;
        let can_be_both = true_allowed_ones & !true_allowed_zeros;
        let must_be_ones = can_be_both & !known & allowed_zeros;
        Ok(default_value | user | must_be_ones)
    }

    /// Validates flags based on allowed one values.
    fn validate_flags_allowed(flags: u64, allowed: u64) -> Result<(), VmxError> {
        let must_be_0 = flags & (!allowed);
        if must_be_0 != 0 {
            let idx = must_be_0.trailing_zeros() as u8;
            Err(VmxError::Disallowed1(VmxFieldError::Unknown, idx))
        } else {
            Ok(())
        }
    }
}

impl<'vmx> core::fmt::Debug for ActiveVmcs<'vmx> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "VMCS {{")?;
        writeln!(f, "    registers {{")?;
        writeln!(f, "        rax: {:#x}", self.get(Register::Rax))?;
        writeln!(f, "        rbx: {:#x}", self.get(Register::Rbx))?;
        writeln!(f, "        rcx: {:#x}", self.get(Register::Rcx))?;
        writeln!(f, "        rdx: {:#x}", self.get(Register::Rdx))?;
        writeln!(f, "        rip: {:#x}", self.get(Register::Rip))?;
        writeln!(f, "        rsp: {:#x}", self.get(Register::Rsp))?;
        writeln!(f, "        rbp: {:#x}", self.get(Register::Rbp))?;
        writeln!(f, "        rsi: {:#x}", self.get(Register::Rsi))?;
        writeln!(f, "        rdi: {:#x}", self.get(Register::Rdi))?;
        writeln!(f, "        r8:  {:#x}", self.get(Register::R8))?;
        writeln!(f, "        r9:  {:#x}", self.get(Register::R9))?;
        writeln!(f, "        r10: {:#x}", self.get(Register::R10))?;
        writeln!(f, "        r11: {:#x}", self.get(Register::R11))?;
        writeln!(f, "        r12: {:#x}", self.get(Register::R12))?;
        writeln!(f, "        r13: {:#x}", self.get(Register::R13))?;
        writeln!(f, "        r14: {:#x}", self.get(Register::R14))?;
        writeln!(f, "        r15: {:#x}", self.get(Register::R15))?;
        writeln!(f, "        cr0: {:#x}", self.get_cr(ControlRegister::Cr0))?;
        writeln!(f, "        cr3: {:#x}", self.get_cr(ControlRegister::Cr3))?;
        writeln!(f, "        cr4: {:#x}", self.get_cr(ControlRegister::Cr4))?;
        writeln!(
            f,
            "        cs.sel: {:#x}",
            self.get16(fields::GuestState16::CsSelector).unwrap()
        )?;
        writeln!(
            f,
            "        cs.base: {:#x}",
            self.get_nat(fields::GuestStateNat::CsBase).unwrap()
        )?;
        writeln!(
            f,
            "        cs.limit: {:#x}",
            self.get32(fields::GuestState32::CsLimit).unwrap()
        )?;
        writeln!(
            f,
            "        cs.ar: {:#x}",
            self.get32(fields::GuestState32::CsAccessRights).unwrap()
        )?;
        writeln!(
            f,
            "        ds.sel: {:#x}",
            self.get16(fields::GuestState16::DsSelector).unwrap()
        )?;
        writeln!(
            f,
            "        ds.base: {:#x}",
            self.get_nat(fields::GuestStateNat::DsBase).unwrap()
        )?;
        writeln!(
            f,
            "        ds.limit: {:#x}",
            self.get32(fields::GuestState32::DsLimit).unwrap()
        )?;
        writeln!(
            f,
            "        ds.ar: {:#x}",
            self.get32(fields::GuestState32::DsAccessRights).unwrap()
        )?;
        writeln!(
            f,
            "        es.sel: {:#x}",
            self.get16(fields::GuestState16::EsSelector).unwrap()
        )?;
        writeln!(
            f,
            "        es.base: {:#x}",
            self.get_nat(fields::GuestStateNat::EsBase).unwrap()
        )?;
        writeln!(
            f,
            "        es.limit: {:#x}",
            self.get32(fields::GuestState32::EsLimit).unwrap()
        )?;
        writeln!(
            f,
            "        es.ar: {:#x}",
            self.get32(fields::GuestState32::EsAccessRights).unwrap()
        )?;
        writeln!(
            f,
            "        fs.sel: {:#x}",
            self.get16(fields::GuestState16::FsSelector).unwrap()
        )?;
        writeln!(
            f,
            "        fs.base: {:#x}",
            self.get_nat(fields::GuestStateNat::FsBase).unwrap()
        )?;
        writeln!(
            f,
            "        fs.limit: {:#x}",
            self.get32(fields::GuestState32::FsLimit).unwrap()
        )?;
        writeln!(
            f,
            "        fs.ar: {:#x}",
            self.get32(fields::GuestState32::FsAccessRights).unwrap()
        )?;
        writeln!(
            f,
            "        gs.sel: {:#x}",
            self.get16(fields::GuestState16::GsSelector).unwrap()
        )?;
        writeln!(
            f,
            "        gs.base: {:#x}",
            self.get_nat(fields::GuestStateNat::GsBase).unwrap()
        )?;
        writeln!(
            f,
            "        gs.limit: {:#x}",
            self.get32(fields::GuestState32::GsLimit).unwrap()
        )?;
        writeln!(
            f,
            "        gs.ar: {:#x}",
            self.get32(fields::GuestState32::GsAccessRights).unwrap()
        )?;
        writeln!(
            f,
            "        ss.sel: {:#x}",
            self.get16(fields::GuestState16::SsSelector).unwrap()
        )?;
        writeln!(
            f,
            "        ss.base: {:#x}",
            self.get_nat(fields::GuestStateNat::SsBase).unwrap()
        )?;
        writeln!(
            f,
            "        ss.limit: {:#x}",
            self.get32(fields::GuestState32::SsLimit).unwrap()
        )?;
        writeln!(
            f,
            "        ss.ar: {:#x}",
            self.get32(fields::GuestState32::SsAccessRights).unwrap()
        )?;
        writeln!(
            f,
            "        ldt.sel: {:#x}",
            self.get16(fields::GuestState16::LdtrSelector).unwrap()
        )?;
        writeln!(
            f,
            "        ldt.base: {:#x}",
            self.get_nat(fields::GuestStateNat::LdtrBase).unwrap()
        )?;
        writeln!(
            f,
            "        ldt.limit: {:#x}",
            self.get32(fields::GuestState32::LdtrLimit).unwrap()
        )?;
        writeln!(
            f,
            "        ldt.ar: {:#x}",
            self.get32(fields::GuestState32::LdtrAccessRights).unwrap()
        )?;
        writeln!(
            f,
            "        tr.sel: {:#x}",
            self.get16(fields::GuestState16::TrSelector).unwrap()
        )?;
        writeln!(
            f,
            "        tr.base: {:#x}",
            self.get_nat(fields::GuestStateNat::TrBase).unwrap()
        )?;
        writeln!(
            f,
            "        tr.limit: {:#x}",
            self.get32(fields::GuestState32::TrLimit).unwrap()
        )?;
        writeln!(
            f,
            "        tr.ar: {:#x}",
            self.get32(fields::GuestState32::TrAccessRights).unwrap()
        )?;
        writeln!(
            f,
            "        idt.base: {:#x}",
            self.get_nat(fields::GuestStateNat::IdtrBase).unwrap()
        )?;
        writeln!(
            f,
            "        idt.limit: {:#x}",
            self.get32(fields::GuestState32::IdtrLimit).unwrap()
        )?;
        writeln!(
            f,
            "        gdt.base: {:#x}",
            self.get_nat(fields::GuestStateNat::GdtrBase).unwrap()
        )?;
        writeln!(
            f,
            "        gdt.limit: {:#x}",
            self.get32(fields::GuestState32::GdtrLimit).unwrap()
        )?;
        writeln!(
            f,
            "        cr0 read shadow: {:#x}",
            self.get_ctrlnat(fields::CtrlNat::Cr0ReadShadow).unwrap()
        )?;
        writeln!(
            f,
            "        cr0 mask: {:#x}",
            self.get_ctrlnat(fields::CtrlNat::Cr0Mask).unwrap()
        )?;
        writeln!(
            f,
            "        cr4 read shadow: {:#x}",
            self.get_ctrlnat(fields::CtrlNat::Cr4ReadShadow).unwrap()
        )?;
        writeln!(
            f,
            "        cr4 mask: {:#x}",
            self.get_ctrlnat(fields::CtrlNat::Cr4Mask).unwrap()
        )?;
        writeln!(
            f,
            "        ia32_efer: {:#x}",
            self.get64(fields::GuestState64::Ia32Efer).unwrap()
        )?;
        writeln!(
            f,
            "        VM Entry Controls: {:?}",
            self.get_vm_entry_cntrls().ok()
        )?;
        writeln!(
            f,
            "        VM Exit Controls: {:?}",
            self.get_vm_exit_ctrls().ok()
        )?;
        writeln!(
            f,
            "        VMCS Pin-Based Controls: {:?}",
            self.get_pin_based_ctrls().ok()
        )?;
        writeln!(
            f,
            "        VMCS PrimaryControls: {:?}",
            self.get_primary_ctrls().ok()
        )?;
        writeln!(
            f,
            "        VMCS SeconaryControls: {:?}",
            self.get_secondary_ctrls().ok()
        )?;
        writeln!(f, "        EPT Ptr: {:#x}", self.get_ept_ptr().unwrap())?;
        writeln!(f, "        EPTP List: {:#x}", self.get_eptp_list().unwrap())?;
        writeln!(f, "    }}")?;
        writeln!(f, "}}")?;

        Ok(())
    }
}

// ——————————————————————————————— Registers ———————————————————————————————— //

/// Virtual CPU registers.
///
//  WARNING: inline assembly depends on the register values, don't change them without updating
//  corresponding assembly!
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Register {
    // Stored in register array
    Rax = 0,
    Rbx = 1,
    Rcx = 2,
    Rdx = 3,
    Rbp = 4,
    Rsi = 5,
    Rdi = 6,
    R8 = 7,
    R9 = 8,
    R10 = 9,
    R11 = 10,
    R12 = 11,
    R13 = 12,
    R14 = 13,
    R15 = 14,

    // Stored in VMCS
    Rsp = 15,
    Rip = 16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlRegister {
    Cr0,
    Cr3,
    Cr4,
    Cr8,
}

pub const REGFILE_SIZE: usize = 15;

// —————————————————————————— Exit Qualifications ——————————————————————————— //

/// A bit vector containing information about VM exit reason.
///
/// The bits must be interpreted differently depending on the exit reason. This types provides a
/// simple way of casting the bits based on the reason.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VmxExitQualification {
    pub raw: usize,
}

impl VmxExitQualification {
    /// Interpretation due to EPT violations.
    pub fn ept_violation(self) -> exit_qualification::EptViolation {
        exit_qualification::EptViolation::from_bits_truncate(self.raw)
    }

    /// Interpretation due to access to a control register.
    pub fn control_register_accesses(self) -> exit_qualification::ControlRegisterAccesses {
        let cr_id = self.raw & 0b1111;
        let cr = match cr_id {
            0 => ControlRegister::Cr0,
            3 => ControlRegister::Cr3,
            4 => ControlRegister::Cr4,
            8 => ControlRegister::Cr8,
            _ => todo!("Handle unknown control register"),
        };
        let reg_id = (self.raw >> 8) & 0b1111;
        let reg = match reg_id {
            0 => Register::Rax,
            1 => Register::Rcx,
            2 => Register::Rdx,
            3 => Register::Rbx,
            4 => Register::Rsp,
            5 => Register::Rbp,
            6 => Register::Rsi,
            7 => Register::Rdi,
            8 => Register::R8,
            9 => Register::R9,
            10 => Register::R10,
            11 => Register::R11,
            12 => Register::R12,
            13 => Register::R13,
            14 => Register::R14,
            15 => Register::R15,
            _ => unreachable!("Can't happen, masked with 4 lowest bits"),
        };
        let payload = ((self.raw >> 16) & 0xFFFF) as u16;
        match (self.raw >> 4) & 0b11 {
            0 => exit_qualification::ControlRegisterAccesses::MovToCr(cr, reg),
            1 => exit_qualification::ControlRegisterAccesses::MovFromCr(cr, reg),
            2 => exit_qualification::ControlRegisterAccesses::Clts(payload),
            3 => {
                if self.raw & (1 << 6) == 0 {
                    exit_qualification::ControlRegisterAccesses::LmswRegister(payload)
                } else {
                    exit_qualification::ControlRegisterAccesses::LmswMemory(payload)
                }
            }
            _ => unreachable!("Can't happen, masked with 2 lowest bits"),
        }
    }
}

// ————————————————————————————————— Tests —————————————————————————————————— //

#[cfg(test)]
mod test {
    use super::*;

    /// See manual Annex A.3.
    #[rustfmt::skip]
    #[test]
    fn ctls_flags_spec() {
        // testing valid combinations
        let spec_0_setting: u64 = 0b001_00_01;
        let spec_1_setting: u64 = 0b011_01_11;
        let user_request:   u32 = 0b000_00_11;
        let known:          u32 = 0b000_11_11;
        let expected:       u32 = 0b001_00_11;

        let spec = (spec_1_setting << 32) + spec_0_setting;
        assert_eq!(ActiveVmcs::get_ctls(user_request, spec, known), Ok(expected));

        // testing disallowed one
        let spec_0_setting: u64 = 0b0_1;
        let spec_1_setting: u64 = 0b0_1;
        let user_request:   u32 = 0b1_1;
        let known:          u32 = 0b1_1;

        let spec = (spec_1_setting << 32) + spec_0_setting;
        assert_eq!(ActiveVmcs::get_ctls(user_request, spec, known), Err(VmxError::Disallowed1(VmxFieldError::Unknown, 1)));

        // testing disallowed zero
        let spec_0_setting: u64 = 0b1;
        let spec_1_setting: u64 = 0b1;
        let user_request:   u32 = 0b0;
        let known:          u32 = 0b1;

        let spec = (spec_1_setting << 32) + spec_0_setting;
        assert_eq!(ActiveVmcs::get_ctls(user_request, spec, known), Err(VmxError::Disallowed0(VmxFieldError::Unknown, 0)));
    }

    /// See manual Annex A.3.
    #[rustfmt::skip]
    #[test]
    fn ctls_flags_true_spec() {
        // testing valid combinations
        let spec_0_setting:      u64 = 0b000_1_00_011;
        let true_spec_0_setting: u64 = 0b001_0_00_010;
        let true_spec_1_setting: u64 = 0b011_1_01_111;
        let user_request:        u32 = 0b000_0_00_111;
        let known:               u32 = 0b000_0_11_111;
        let expected:            u32 = 0b001_1_00_111;

        let spec = spec_0_setting;
        let true_spec = (true_spec_1_setting << 32) + true_spec_0_setting;
        assert_eq!(ActiveVmcs::get_true_ctls(user_request, spec, true_spec, known), Ok(expected));

        // testing disallowed one
        let spec_0_setting:      u64 = 0b0_1;
        let true_spec_0_setting: u64 = 0b0_0;
        let true_spec_1_setting: u64 = 0b0_1;
        let user_request:        u32 = 0b1_1;
        let known:               u32 = 0b1_1;

        let spec = spec_0_setting;
        let true_spec = (true_spec_1_setting << 32) + true_spec_0_setting;
        assert_eq!(
            ActiveVmcs::get_true_ctls(user_request, spec, true_spec, known),
            Err(VmxError::Disallowed1(VmxFieldError::Unknown, 1)),
        );

        // testing disallowed zero
        let spec_0_setting:      u64 = 0b1;
        let true_spec_0_setting: u64 = 0b1;
        let true_spec_1_setting: u64 = 0b0;
        let user_request:        u32 = 0b0;
        let known:               u32 = 0b1;

        let spec = spec_0_setting;
        let true_spec = (true_spec_1_setting << 32) + true_spec_0_setting;
        assert_eq!(
            ActiveVmcs::get_true_ctls(user_request, spec, true_spec, known),
            Err(VmxError::Disallowed0(VmxFieldError::Unknown, 0)),
        );
    }
}

// ————————————————————————————————— Utils —————————————————————————————————— //

fn read_cr4() -> u64 {
    let cr4: u64;
    unsafe {
        asm! {
            "mov {}, cr4",
            out(reg) cr4,
            options(nomem, nostack, preserves_flags),
        };
    }
    cr4
}

unsafe fn write_cr4(cr4: u64) {
    asm! {
        "mov cr4, {}",
        in(reg) cr4,
        options(nomem, nostack, preserves_flags),
    };
}
