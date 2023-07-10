//! VMCS fields
//!
//! This module lists the different VMCS fields.
//!
//! Fields are classified according to their width:
//! - 16 bits
//! - 32 bits
//! - 64 bits
//! - Natural width (32 or 64 bits depending on the architecture)
//!
//! In addition, there a four distinct categories of fields:
//! - Control fields
//! - Read-only fields
//! - Guest state
//! - Host state
//!
//! To enforce correct usage of `vmwrite`, i.e. passing arguments with expected width, fields are
//! grouped by category and width and implements a trait enabling `vmwrite` with the expected
//! width.
//!
//! NOTE: `vmwrite` operates on the current VMCS.
//!
//! Usage:
//!
//! ```no_run
//! // Bring all traits to current scope, this avoid having to import each trait individually
//! use vmx::fields::traits::*;
//!
//! // Import the desired fields
//! use vmx::fields::Ctrl64;
//!
//! // Write a value into that field
//! unsafe { Ctrl64::IoBitmapA.vmwrite(0) };
//! ```
//!
//! See Intel 3D Appendix B.

// ————————————————————————————————— Traits ————————————————————————————————— //

// Bring all traits into current scope
use traits::*;

use super::VmxError;
use crate::msr::VMX_VMCS_ENUM;
use crate::raw;

pub mod traits {
    use super::*;

    pub trait VmcsField {
        fn raw(&self) -> u32;
    }

    /// A VMCS field containing a 64 bits value.
    pub trait VmcsField64: VmcsField {
        /// Writes a field to the current VMCS.
        unsafe fn vmwrite(&self, value: u64) -> Result<(), VmxError> {
            raw::vmwrite(self.raw() as u64, value)
        }

        /// Reads a field to the current VMCS.
        unsafe fn vmread(&self) -> Result<u64, VmxError> {
            raw::vmread(self.raw() as u64)
        }
    }

    /// A VMCS field containing a 32 bits value.
    pub trait VmcsField32: VmcsField {
        /// Writes a field to the current VMCS.
        unsafe fn vmwrite(&self, value: u32) -> Result<(), VmxError> {
            raw::vmwrite(self.raw() as u64, value as u64)
        }

        /// Reads a field to the current VMCS.
        unsafe fn vmread(&self) -> Result<u32, VmxError> {
            raw::vmread(self.raw() as u64).map(|value| value as u32)
        }
    }

    /// A VMCS field containing a 16 bits value.
    pub trait VmcsField16: VmcsField {
        /// Writes a field to the current VMCS.
        unsafe fn vmwrite(&self, value: u16) -> Result<(), VmxError> {
            raw::vmwrite(self.raw() as u64, value as u64)
        }

        /// Reads a field to the current VMCS.
        unsafe fn vmread(&self) -> Result<u16, VmxError> {
            raw::vmread(self.raw() as u64).map(|value| value as u16)
        }
    }

    /// A VMCS field containing a natural width value (i.e. 32 bits on 32 bits systems, 64 bits on 64
    /// bits systems).
    pub trait VmcsFieldNat: VmcsField {
        /// Writes a field to the current VMCS.
        unsafe fn vmwrite(&self, value: usize) -> Result<(), VmxError> {
            raw::vmwrite(self.raw() as u64, value as u64)
        }

        /// Reads a field to the current VMCS.
        unsafe fn vmread(&self) -> Result<usize, VmxError> {
            raw::vmread(self.raw() as u64).map(|value| value as usize)
        }
    }

    /// A VMCS read-only field containing a 16 bits value.
    pub trait VmcsField16Ro: VmcsField {
        /// Reads a field to the current VMCS.
        unsafe fn vmread(&self) -> Result<u16, VmxError> {
            raw::vmread(self.raw() as u64).map(|value| value as u16)
        }
    }

    /// A VMCS read-only field containing a 32 bits value.
    pub trait VmcsField32Ro: VmcsField {
        /// Reads a field to the current VMCS.
        unsafe fn vmread(&self) -> Result<u32, VmxError> {
            raw::vmread(self.raw() as u64).map(|value| value as u32)
        }
    }

    /// A VMCS read-only field containing a 64 bits value.
    pub trait VmcsField64Ro: VmcsField {
        /// reads a field to the current VMCS.
        unsafe fn vmread(&self) -> Result<u64, VmxError> {
            raw::vmread(self.raw() as u64)
        }
    }

    /// A VMCS read-only field containing a natural-width value.
    pub trait VmcsFieldNatRo: VmcsField {
        /// Reads a field to the current VMCS.
        unsafe fn vmread(&self) -> Result<usize, VmxError> {
            raw::vmread(self.raw() as u64).map(|value| value as usize)
        }
    }

    /// A trait to check if a given field is supported by the hardware.
    pub trait VmcsFieldSupport: VmcsField {
        /// Returns true if the field is for sure not supported by the current hardware.
        /// Note that the field might still be unsupported if false is returned.
        ///
        /// TODO: Can we in fact precisely predict which field is supported? I'm not sure with the
        /// manual's wording.
        fn is_unsupported(&self) -> bool {
            // SAFETY: This MSR is always supported
            let vmcs_enum = unsafe { VMX_VMCS_ENUM.read() };
            // the bits 9:1 of the MSR must be greater than bits 9:1 of the field encoding.
            // See Intel manual volume 3 annex A.9.
            (self.raw() as u64 & 0b1111111110) > vmcs_enum
        }
    }
}

// ————————————————————————————— Control Fields ————————————————————————————— //

/// Implements the given field trait for a `#[repr(32)]` struct.
macro_rules! impl_field_for {
    ($field:ident, $struc:ident) => {
        impl VmcsField for $struc {
            #[inline]
            fn raw(&self) -> u32 {
                *self as u32
            }
        }

        impl $field for $struc {}
        impl VmcsFieldSupport for $struc {}
    };
}

/// VMCS fields encoding of 32 bits control fields.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Ctrl32 {
    PinBasedExecCtrls             = 0x00004000,
    PrimaryProcBasedExecCtrls     = 0x00004002,
    ExceptionBitmap               = 0x00004004,
    PageFaultErrCodeMask          = 0x00004006,
    PageFaultErrCodeMatch         = 0x00004008,
    Cr3TargetCount                = 0x0000400A,
    VmExitCtrls                   = 0x0000400C,
    VmExitMsrStoreCount           = 0x0000400E,
    VmExitMsrLoadCount            = 0x00004010,
    VmEntryCtrls                  = 0x00004012,
    VmEntryMsrLoadCount           = 0x00004014,
    VmEntryIntInfoField           = 0x00004016,
    VmEntryExceptErrCode          = 0x00004018,
    VmEntryInstrLength            = 0x0000401A,
    TprThreshold                  = 0x0000401C,
    SecondaryProcBasedVmExecCtrls = 0x0000401E,
    PleGap                        = 0x00004020,
    PleWindow                     = 0x00004022,
}

impl_field_for!(VmcsField32, Ctrl32);

/// VMCS fields encoding of 64 bits control fields.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Ctrl64 {
    IoBitmapA          = 0x00002000,
    IoBitmapB          = 0x00002002,
    MsrBitmaps         = 0x00002004,
    VmExitMsrStoreAddr = 0x00002006,
    VmExitMsrLoadAddr  = 0x00002008,
    VmEntryMsrLoadAddr = 0x0000200A,
    ExecVmcsPtr        = 0x0000200C,
    PmlAddr            = 0x0000200E,
    TscOffset          = 0x00002010,
    VirtApicAddr       = 0x00002012,
    ApicAccessAddr     = 0x00002014,
    PostedIntDescAddr  = 0x00002016,
    VmFuncCtrls        = 0x00002018,
    EptPtr             = 0x0000201A,
    EoiExitBitmap0     = 0x0000201C,
    EoiExitBitmap1     = 0x0000201E,
    EoiExitBitmap2     = 0x00002020,
    EoiExitBitmap3     = 0x00002022,
    EptpListAddr       = 0x00002024,
    VmreadBitmapAddr   = 0x00002026,
    VmwriteBitmapAddr  = 0x00002028,
    VirtExceptInfAddr  = 0x0000202A,
    XssExitBitmap      = 0x0000202C,
    EnclsExitBitmap    = 0x0000202E,
    TscMultiplier      = 0x00002032,
}

impl_field_for!(VmcsField64, Ctrl64);

/// VMCS fields encoding of natural width control fields.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CtrlNat {
    Cr0Mask         = 0x00006000,
    Cr4Mask         = 0x00006002,
    Cr0ReadShadow   = 0x00006004,
    Cr4ReadShadow   = 0x00006006,
    Cr3TargetValue0 = 0x00006008,
    Cr3TargetValue1 = 0x0000600A,
    Cr3TargetValue2 = 0x0000600C,
    Cr3TargetValue3 = 0x0000600E,
}

impl_field_for!(VmcsFieldNat, CtrlNat);

// ——————————————————————————— Host State Fields ———————————————————————————— //

/// VMCS fields encoding of 16 bits host state fields.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HostState16 {
    EsSelector = 0x00000C00,
    CsSelector = 0x00000C02,
    SsSelector = 0x00000C04,
    DsSelector = 0x00000C06,
    FsSelector = 0x00000C08,
    GsSelector = 0x00000C0A,
    TrSelector = 0x00000C0C,
}

impl_field_for!(VmcsField16, HostState16);

/// VMCS fields encoding of 32 bits host state fields.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HostState32 {
    Ia32SysenterCs = 0x00004C00,
}

impl_field_for!(VmcsField32, HostState32);

/// VMCS fields encoding of 64 bits host state fields.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HostState64 {
    Ia32Pat            = 0x00002C00,
    Ia32Efer           = 0x00002C02,
    Ia32PerfGlobalCtrl = 0x00002C04,
}

impl_field_for!(VmcsField64, HostState64);

/// VMCS fields encoding of natural width host state fields.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HostStateNat {
    Cr0             = 0x00006C00,
    Cr3             = 0x00006C02,
    Cr4             = 0x00006C04,
    FsBase          = 0x00006C06,
    GsBase          = 0x00006C08,
    TrBase          = 0x00006C0A,
    GdtrBase        = 0x00006C0C,
    IdtrBase        = 0x00006C0E,
    Ia32SysenterEsp = 0x00006C10,
    Ia32SysenterEip = 0x00006C12,
    Rsp             = 0x00006C14,
    Rip             = 0x00006C16,
}

impl_field_for!(VmcsFieldNat, HostStateNat);

// ——————————————————————————— Guest State Fields ——————————————————————————— //

/// VMCS fields encoding of 16 bits guest state fields.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GuestState16 {
    EsSelector      = 0x00000800,
    CsSelector      = 0x00000802,
    SsSelector      = 0x00000804,
    DsSelector      = 0x00000806,
    FsSelector      = 0x00000808,
    GsSelector      = 0x0000080A,
    LdtrSelector    = 0x0000080C,
    TrSelector      = 0x0000080E,
    InterruptStatus = 0x00000810,
    PmlIndex        = 0x00000812,
}

impl_field_for!(VmcsField16, GuestState16);

/// VMCS fields encoding of 32 bits guest state fields.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GuestState32 {
    EsLimit                 = 0x00004800,
    CsLimit                 = 0x00004802,
    SsLimit                 = 0x00004804,
    DsLimit                 = 0x00004806,
    FsLimit                 = 0x00004808,
    GsLimit                 = 0x0000480A,
    LdtrLimit               = 0x0000480C,
    TrLimit                 = 0x0000480E,
    GdtrLimit               = 0x00004810,
    IdtrLimit               = 0x00004812,
    EsAccessRights          = 0x00004814,
    CsAccessRights          = 0x00004816,
    SsAccessRights          = 0x00004818,
    DsAccessRights          = 0x0000481A,
    FsAccessRights          = 0x0000481C,
    GsAccessRights          = 0x0000481E,
    LdtrAccessRights        = 0x00004820,
    TrAccessRights          = 0x00004822,
    InterruptibilityState   = 0x00004824,
    ActivityState           = 0x00004826,
    Smbase                  = 0x00004828,
    Ia32SysenterCs          = 0x0000482A,
    /// Only exists if processor support VMX preemption timer.
    VmxPreemptionTimerValue = 0x0000482E,
}

impl_field_for!(VmcsField32, GuestState32);

/// VMCS fields encoding of 32 bits read-only guest state fields.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GuestState32Ro {
    VmInstructionError      = 0x00004400,
    ExitReason              = 0x00004402,
    VmExitInterruptInfo     = 0x00004404,
    VmExitInterruptErrCode  = 0x00004406,
    IdtVecoringInfoField    = 0x00004408,
    IdtVectoringErrCode     = 0x0000440A,
    VmExitInstructionLength = 0x0000440C,
    VmExitInstructionInfo   = 0x0000440E,
}

impl_field_for!(VmcsField32Ro, GuestState32Ro);

/// VMCS fields encoding of 64 bits guest state fields.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GuestState64 {
    VmcsLinkPtr        = 0x00002800,
    Ia32Debugctl       = 0x00002802,
    Ia32Pat            = 0x00002804,
    Ia32Efer           = 0x00002806,
    Ia32PerfGlobalCtrl = 0x00002808,
    Pdpte0             = 0x0000280A,
    Pdpte1             = 0x0000280C,
    Ptpte2             = 0x0000280E,
    Pdpte3             = 0x00002810,
    Ia32Binddfgs       = 0x00002812,
}

impl_field_for!(VmcsField64, GuestState64);

/// VMCS fields encoding of 64 bits read-only guest state fields.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GuestState64Ro {
    GuestPhysAddr = 0x00002400,
}

impl_field_for!(VmcsField64Ro, GuestState64Ro);

/// VMCS fields encoding of natural width guest state fields.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GuestStateNat {
    Cr0                = 0x00006800,
    Cr3                = 0x00006802,
    Cr4                = 0x00006804,
    EsBase             = 0x00006806,
    CsBase             = 0x00006808,
    SsBase             = 0x0000680A,
    DsBase             = 0x0000680C,
    FsBase             = 0x0000680E,
    GsBase             = 0x00006810,
    LdtrBase           = 0x00006812,
    TrBase             = 0x00006814,
    GdtrBase           = 0x00006816,
    IdtrBase           = 0x00006818,
    Dr7                = 0x0000681A,
    Rsp                = 0x0000681C,
    Rip                = 0x0000681E,
    Rflags             = 0x00006820,
    PendingDebugExcept = 0x00006822,
    Ia32SysenterEsp    = 0x00006824,
    Ia32SysenterEip    = 0x00006826,
}

impl_field_for!(VmcsFieldNat, GuestStateNat);

/// VMCS fields encoding of natural width guest state read-only fields.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GuestStateNatRo {
    ExitQualification = 0x00006400,
    IoRcx             = 0x00006402,
    IoRsi             = 0x00006404,
    IoRdi             = 0x00006406,
    IoRip             = 0x00006408,
    GuestLinearAddr   = 0x0000640A,
}

impl_field_for!(VmcsFieldNatRo, GuestStateNatRo);
