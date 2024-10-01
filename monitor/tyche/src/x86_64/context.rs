use capa_engine::context::{RegisterContext, RegisterGroup};
use capa_engine::Handle;
use spin::Mutex;
use vmx::bitmaps::{PinbasedControls, PrimaryControls, SecondaryControls};
use vmx::fields::{VmcsField, VmcsFieldWidth};
use vmx::{ActiveVmcs, VmxError};

use crate::rcframe::{RCFrame, RCFramePool};

pub const MAX_CPUID_ENTRIES: usize = 50;

trait ContextRegisterx86 {
    fn as_vmcs_field(&self) -> VmcsField;
    fn from_vmcs_field(field: VmcsField) -> Option<Self>
    where
        Self: Sized;
    fn from_usize(v: usize) -> Self;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum ContextGpx86 {
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
    Lstar = 15,
}

impl ContextGpx86 {
    pub fn as_vmcs_field(&self) -> VmcsField {
        match self {
            Self::Rax => VmcsField::GuestRax,
            Self::Rbx => VmcsField::GuestRbx,
            Self::Rcx => VmcsField::GuestRcx,
            Self::Rdx => VmcsField::GuestRdx,
            Self::Rbp => VmcsField::GuestRbp,
            Self::Rsi => VmcsField::GuestRsi,
            Self::Rdi => VmcsField::GuestRdi,
            Self::R8 => VmcsField::GuestR8,
            Self::R9 => VmcsField::GuestR9,
            Self::R10 => VmcsField::GuestR10,
            Self::R11 => VmcsField::GuestR11,
            Self::R12 => VmcsField::GuestR12,
            Self::R13 => VmcsField::GuestR13,
            Self::R14 => VmcsField::GuestR14,
            Self::R15 => VmcsField::GuestR15,
            Self::Lstar => VmcsField::GuestLstar,
        }
    }
    pub fn from_vmcs_field(field: VmcsField) -> Option<Self> {
        match field {
            VmcsField::GuestRax => Some(Self::Rax),
            VmcsField::GuestRbx => Some(Self::Rbx),
            VmcsField::GuestRcx => Some(Self::Rcx),
            VmcsField::GuestRdx => Some(Self::Rdx),
            VmcsField::GuestRbp => Some(Self::Rbp),
            VmcsField::GuestRsi => Some(Self::Rsi),
            VmcsField::GuestRdi => Some(Self::Rdi),
            VmcsField::GuestR8 => Some(Self::R8),
            VmcsField::GuestR9 => Some(Self::R9),
            VmcsField::GuestR10 => Some(Self::R10),
            VmcsField::GuestR11 => Some(Self::R11),
            VmcsField::GuestR12 => Some(Self::R12),
            VmcsField::GuestR13 => Some(Self::R13),
            VmcsField::GuestR14 => Some(Self::R14),
            VmcsField::GuestR15 => Some(Self::R15),
            VmcsField::GuestLstar => Some(Self::Lstar),
            _ => None,
        }
    }

    pub fn from_usize(v: usize) -> Self {
        match v {
            0 => Self::Rax,
            1 => Self::Rbx,
            2 => Self::Rcx,
            3 => Self::Rdx,
            4 => Self::Rbp,
            5 => Self::Rsi,
            6 => Self::Rdi,
            7 => Self::R8,
            8 => Self::R9,
            9 => Self::R10,
            10 => Self::R11,
            11 => Self::R12,
            12 => Self::R13,
            13 => Self::R14,
            14 => Self::R15,
            15 => Self::Lstar,
            _ => panic!("Invalid value"),
        }
    }
    pub const fn size() -> usize {
        return Self::Lstar as usize + 1;
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum Context32x86 {
    PinBasedVmExecControl = 0,
    CpuBasedVmExecControl = 1,
    ExceptionBitmap = 2,
    PageFaultErrorCodeMask = 3,
    PageFaultErrorCodeMatch = 4,
    Cr3TargetCount = 5,
    VmExitControls = 6,
    VmExitMsrStoreCount = 7,
    VmExitMsrLoadCount = 8,
    VmEntryControls = 9,
    VmEntryMsrLoadCount = 10,
    VmEntryIntrInfoField = 11,
    VmEntryExceptionErrorCode = 12,
    VmEntryInstructionLen = 13,
    TprThreshold = 14,
    SecondaryVmExecControl = 15,
    PleGap = 16,
    PleWindow = 17,
    NotifyWindow = 18,
    VmInstructionError = 19,
    VmExitReason = 20,
    VmExitIntrInfo = 21,
    VmExitIntrErrorCode = 22,
    IdtVectoringInfoField = 23,
    IdtVectoringErrorCode = 24,
    VmExitInstructionLen = 25,
    VmxInstructionInfo = 26,
    GuestEsLimit = 27,
    GuestCsLimit = 28,
    GuestSsLimit = 29,
    GuestDsLimit = 30,
    GuestFsLimit = 31,
    GuestGsLimit = 32,
    GuestLdtrLimit = 33,
    GuestTrLimit = 34,
    GuestGdtrLimit = 35,
    GuestIdtrLimit = 36,
    GuestEsArBytes = 37,
    GuestCsArBytes = 38,
    GuestSsArBytes = 39,
    GuestDsArBytes = 40,
    GuestFsArBytes = 41,
    GuestGsArBytes = 42,
    GuestLdtrArBytes = 43,
    GuestTrArBytes = 44,
    GuestInterruptibilityInfo = 45,
    GuestActivityState = 46,
    GuestSysenterCs = 47,
    VmxPreemptionTimerValue = 48,
}

impl Context32x86 {
    pub fn as_vmcs_field(&self) -> VmcsField {
        match self {
            Self::PinBasedVmExecControl => VmcsField::PinBasedVmExecControl,
            Self::CpuBasedVmExecControl => VmcsField::CpuBasedVmExecControl,
            Self::ExceptionBitmap => VmcsField::ExceptionBitmap,
            Self::PageFaultErrorCodeMask => VmcsField::PageFaultErrorCodeMask,
            Self::PageFaultErrorCodeMatch => VmcsField::PageFaultErrorCodeMatch,
            Self::Cr3TargetCount => VmcsField::Cr3TargetCount,
            Self::VmExitControls => VmcsField::VmExitControls,
            Self::VmExitMsrStoreCount => VmcsField::VmExitMsrStoreCount,
            Self::VmExitMsrLoadCount => VmcsField::VmExitMsrLoadCount,
            Self::VmEntryControls => VmcsField::VmEntryControls,
            Self::VmEntryMsrLoadCount => VmcsField::VmEntryMsrLoadCount,
            Self::VmEntryIntrInfoField => VmcsField::VmEntryIntrInfoField,
            Self::VmEntryExceptionErrorCode => VmcsField::VmEntryExceptionErrorCode,
            Self::VmEntryInstructionLen => VmcsField::VmEntryInstructionLen,
            Self::TprThreshold => VmcsField::TprThreshold,
            Self::SecondaryVmExecControl => VmcsField::SecondaryVmExecControl,
            Self::PleGap => VmcsField::PleGap,
            Self::PleWindow => VmcsField::PleWindow,
            Self::NotifyWindow => VmcsField::NotifyWindow,
            Self::VmInstructionError => VmcsField::VmInstructionError,
            Self::VmExitReason => VmcsField::VmExitReason,
            Self::VmExitIntrInfo => VmcsField::VmExitIntrInfo,
            Self::VmExitIntrErrorCode => VmcsField::VmExitIntrErrorCode,
            Self::IdtVectoringInfoField => VmcsField::IdtVectoringInfoField,
            Self::IdtVectoringErrorCode => VmcsField::IdtVectoringErrorCode,
            Self::VmExitInstructionLen => VmcsField::VmExitInstructionLen,
            Self::VmxInstructionInfo => VmcsField::VmxInstructionInfo,
            Self::GuestEsLimit => VmcsField::GuestEsLimit,
            Self::GuestCsLimit => VmcsField::GuestCsLimit,
            Self::GuestSsLimit => VmcsField::GuestSsLimit,
            Self::GuestDsLimit => VmcsField::GuestDsLimit,
            Self::GuestFsLimit => VmcsField::GuestFsLimit,
            Self::GuestGsLimit => VmcsField::GuestGsLimit,
            Self::GuestLdtrLimit => VmcsField::GuestLdtrLimit,
            Self::GuestTrLimit => VmcsField::GuestTrLimit,
            Self::GuestGdtrLimit => VmcsField::GuestGdtrLimit,
            Self::GuestIdtrLimit => VmcsField::GuestIdtrLimit,
            Self::GuestEsArBytes => VmcsField::GuestEsArBytes,
            Self::GuestCsArBytes => VmcsField::GuestCsArBytes,
            Self::GuestSsArBytes => VmcsField::GuestSsArBytes,
            Self::GuestDsArBytes => VmcsField::GuestDsArBytes,
            Self::GuestFsArBytes => VmcsField::GuestFsArBytes,
            Self::GuestGsArBytes => VmcsField::GuestGsArBytes,
            Self::GuestLdtrArBytes => VmcsField::GuestLdtrArBytes,
            Self::GuestTrArBytes => VmcsField::GuestTrArBytes,
            Self::GuestInterruptibilityInfo => VmcsField::GuestInterruptibilityInfo,
            Self::GuestActivityState => VmcsField::GuestActivityState,
            Self::GuestSysenterCs => VmcsField::GuestSysenterCs,
            Self::VmxPreemptionTimerValue => VmcsField::VmxPreemptionTimerValue,
        }
    }

    pub fn from_vmcs_field(field: VmcsField) -> Option<Self> {
        match field {
            VmcsField::PinBasedVmExecControl => Some(Self::PinBasedVmExecControl),
            VmcsField::CpuBasedVmExecControl => Some(Self::CpuBasedVmExecControl),
            VmcsField::ExceptionBitmap => Some(Self::ExceptionBitmap),
            VmcsField::PageFaultErrorCodeMask => Some(Self::PageFaultErrorCodeMask),
            VmcsField::PageFaultErrorCodeMatch => Some(Self::PageFaultErrorCodeMatch),
            VmcsField::Cr3TargetCount => Some(Self::Cr3TargetCount),
            VmcsField::VmExitControls => Some(Self::VmExitControls),
            VmcsField::VmExitMsrStoreCount => Some(Self::VmExitMsrStoreCount),
            VmcsField::VmExitMsrLoadCount => Some(Self::VmExitMsrLoadCount),
            VmcsField::VmEntryControls => Some(Self::VmEntryControls),
            VmcsField::VmEntryMsrLoadCount => Some(Self::VmEntryMsrLoadCount),
            VmcsField::VmEntryIntrInfoField => Some(Self::VmEntryIntrInfoField),
            VmcsField::VmEntryExceptionErrorCode => Some(Self::VmEntryExceptionErrorCode),
            VmcsField::VmEntryInstructionLen => Some(Self::VmEntryInstructionLen),
            VmcsField::TprThreshold => Some(Self::TprThreshold),
            VmcsField::SecondaryVmExecControl => Some(Self::SecondaryVmExecControl),
            VmcsField::PleGap => Some(Self::PleGap),
            VmcsField::PleWindow => Some(Self::PleWindow),
            VmcsField::NotifyWindow => Some(Self::NotifyWindow),
            VmcsField::VmInstructionError => Some(Self::VmInstructionError),
            VmcsField::VmExitReason => Some(Self::VmExitReason),
            VmcsField::VmExitIntrInfo => Some(Self::VmExitIntrInfo),
            VmcsField::VmExitIntrErrorCode => Some(Self::VmExitIntrErrorCode),
            VmcsField::IdtVectoringInfoField => Some(Self::IdtVectoringInfoField),
            VmcsField::IdtVectoringErrorCode => Some(Self::IdtVectoringErrorCode),
            VmcsField::VmExitInstructionLen => Some(Self::VmExitInstructionLen),
            VmcsField::VmxInstructionInfo => Some(Self::VmxInstructionInfo),
            VmcsField::GuestEsLimit => Some(Self::GuestEsLimit),
            VmcsField::GuestCsLimit => Some(Self::GuestCsLimit),
            VmcsField::GuestSsLimit => Some(Self::GuestSsLimit),
            VmcsField::GuestDsLimit => Some(Self::GuestDsLimit),
            VmcsField::GuestFsLimit => Some(Self::GuestFsLimit),
            VmcsField::GuestGsLimit => Some(Self::GuestGsLimit),
            VmcsField::GuestLdtrLimit => Some(Self::GuestLdtrLimit),
            VmcsField::GuestTrLimit => Some(Self::GuestTrLimit),
            VmcsField::GuestGdtrLimit => Some(Self::GuestGdtrLimit),
            VmcsField::GuestIdtrLimit => Some(Self::GuestIdtrLimit),
            VmcsField::GuestEsArBytes => Some(Self::GuestEsArBytes),
            VmcsField::GuestCsArBytes => Some(Self::GuestCsArBytes),
            VmcsField::GuestSsArBytes => Some(Self::GuestSsArBytes),
            VmcsField::GuestDsArBytes => Some(Self::GuestDsArBytes),
            VmcsField::GuestFsArBytes => Some(Self::GuestFsArBytes),
            VmcsField::GuestGsArBytes => Some(Self::GuestGsArBytes),
            VmcsField::GuestLdtrArBytes => Some(Self::GuestLdtrArBytes),
            VmcsField::GuestTrArBytes => Some(Self::GuestTrArBytes),
            VmcsField::GuestInterruptibilityInfo => Some(Self::GuestInterruptibilityInfo),
            VmcsField::GuestActivityState => Some(Self::GuestActivityState),
            VmcsField::GuestSysenterCs => Some(Self::GuestSysenterCs),
            VmcsField::VmxPreemptionTimerValue => Some(Self::VmxPreemptionTimerValue),
            _ => None,
        }
    }

    pub fn from_usize(v: usize) -> Self {
        match v {
            0 => Self::PinBasedVmExecControl,
            1 => Self::CpuBasedVmExecControl,
            2 => Self::ExceptionBitmap,
            3 => Self::PageFaultErrorCodeMask,
            4 => Self::PageFaultErrorCodeMatch,
            5 => Self::Cr3TargetCount,
            6 => Self::VmExitControls,
            7 => Self::VmExitMsrStoreCount,
            8 => Self::VmExitMsrLoadCount,
            9 => Self::VmEntryControls,
            10 => Self::VmEntryMsrLoadCount,
            11 => Self::VmEntryIntrInfoField,
            12 => Self::VmEntryExceptionErrorCode,
            13 => Self::VmEntryInstructionLen,
            14 => Self::TprThreshold,
            15 => Self::SecondaryVmExecControl,
            16 => Self::PleGap,
            17 => Self::PleWindow,
            18 => Self::NotifyWindow,
            19 => Self::VmInstructionError,
            20 => Self::VmExitReason,
            21 => Self::VmExitIntrInfo,
            22 => Self::VmExitIntrErrorCode,
            23 => Self::IdtVectoringInfoField,
            24 => Self::IdtVectoringErrorCode,
            25 => Self::VmExitInstructionLen,
            26 => Self::VmxInstructionInfo,
            27 => Self::GuestEsLimit,
            28 => Self::GuestCsLimit,
            29 => Self::GuestSsLimit,
            30 => Self::GuestDsLimit,
            31 => Self::GuestFsLimit,
            32 => Self::GuestGsLimit,
            33 => Self::GuestLdtrLimit,
            34 => Self::GuestTrLimit,
            35 => Self::GuestGdtrLimit,
            36 => Self::GuestIdtrLimit,
            37 => Self::GuestEsArBytes,
            38 => Self::GuestCsArBytes,
            39 => Self::GuestSsArBytes,
            40 => Self::GuestDsArBytes,
            41 => Self::GuestFsArBytes,
            42 => Self::GuestGsArBytes,
            43 => Self::GuestLdtrArBytes,
            44 => Self::GuestTrArBytes,
            45 => Self::GuestInterruptibilityInfo,
            46 => Self::GuestActivityState,
            47 => Self::GuestSysenterCs,
            48 => Self::VmxPreemptionTimerValue,
            _ => panic!("Invalid value"),
        }
    }

    pub const fn size() -> usize {
        return Self::VmxPreemptionTimerValue as usize + 1;
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum Context64x86 {
    IoBitmapA = 0,
    IoBitmapB = 1,
    MsrBitmap = 2,
    VmExitMsrStoreAddr = 3,
    VmExitMsrLoadAddr = 4,
    VmEntryMsrLoadAddr = 5,
    PmlAddress = 6,
    TscOffset = 7,
    VirtualApicPageAddr = 8,
    ApicAccessAddr = 9,
    PostedIntrDescAddr = 10,
    VmFunctionControl = 11,
    EptPointer = 12,
    EoiExitBitmap0 = 13,
    EoiExitBitmap1 = 14,
    EoiExitBitmap2 = 15,
    EoiExitBitmap3 = 16,
    EptpListAddress = 17,
    VmreadBitmap = 18,
    VmwriteBitmap = 19,
    XssExitBitmap = 20,
    EnclsExitingBitmap = 21,
    TscMultiplier = 22,
    TertiaryVmExecControl = 23,
    PidPointerTable = 24,
    GuestPhysicalAddress = 25,
    VmcsLinkPointer = 26,
    GuestIa32Debugctl = 27,
    GuestIa32Pat = 28,
    GuestIa32Efer = 29,
    GuestIa32PerfGlobalCtrl = 30,
    GuestPdptr0 = 31,
    GuestPdptr1 = 32,
    GuestPdptr2 = 33,
    GuestPdptr3 = 34,
    GuestBndcfgs = 35,
    GuestIa32RtitCtl = 36,
    HostIa32Pat = 37,
    HostIa32Efer = 38,
    HostIa32PerfGlobalCtrl = 39,
}

impl Context64x86 {
    pub fn as_vmcs_field(&self) -> VmcsField {
        match self {
            Self::IoBitmapA => VmcsField::IoBitmapA,
            Self::IoBitmapB => VmcsField::IoBitmapB,
            Self::MsrBitmap => VmcsField::MsrBitmap,
            Self::VmExitMsrStoreAddr => VmcsField::VmExitMsrStoreAddr,
            Self::VmExitMsrLoadAddr => VmcsField::VmExitMsrLoadAddr,
            Self::VmEntryMsrLoadAddr => VmcsField::VmEntryMsrLoadAddr,
            Self::PmlAddress => VmcsField::PmlAddress,
            Self::TscOffset => VmcsField::TscOffset,
            Self::VirtualApicPageAddr => VmcsField::VirtualApicPageAddr,
            Self::ApicAccessAddr => VmcsField::ApicAccessAddr,
            Self::PostedIntrDescAddr => VmcsField::PostedIntrDescAddr,
            Self::VmFunctionControl => VmcsField::VmFunctionControl,
            Self::EptPointer => VmcsField::EptPointer,
            Self::EoiExitBitmap0 => VmcsField::EoiExitBitmap0,
            Self::EoiExitBitmap1 => VmcsField::EoiExitBitmap1,
            Self::EoiExitBitmap2 => VmcsField::EoiExitBitmap2,
            Self::EoiExitBitmap3 => VmcsField::EoiExitBitmap3,
            Self::EptpListAddress => VmcsField::EptpListAddress,
            Self::VmreadBitmap => VmcsField::VmreadBitmap,
            Self::VmwriteBitmap => VmcsField::VmwriteBitmap,
            Self::XssExitBitmap => VmcsField::XssExitBitmap,
            Self::EnclsExitingBitmap => VmcsField::EnclsExitingBitmap,
            Self::TscMultiplier => VmcsField::TscMultiplier,
            Self::TertiaryVmExecControl => VmcsField::TertiaryVmExecControl,
            Self::PidPointerTable => VmcsField::PidPointerTable,
            Self::GuestPhysicalAddress => VmcsField::GuestPhysicalAddress,
            Self::VmcsLinkPointer => VmcsField::VmcsLinkPointer,
            Self::GuestIa32Debugctl => VmcsField::GuestIa32Debugctl,
            Self::GuestIa32Pat => VmcsField::GuestIa32Pat,
            Self::GuestIa32Efer => VmcsField::GuestIa32Efer,
            Self::GuestIa32PerfGlobalCtrl => VmcsField::GuestIa32PerfGlobalCtrl,
            Self::GuestPdptr0 => VmcsField::GuestPdptr0,
            Self::GuestPdptr1 => VmcsField::GuestPdptr1,
            Self::GuestPdptr2 => VmcsField::GuestPdptr2,
            Self::GuestPdptr3 => VmcsField::GuestPdptr3,
            Self::GuestBndcfgs => VmcsField::GuestBndcfgs,
            Self::GuestIa32RtitCtl => VmcsField::GuestIa32RtitCtl,
            Self::HostIa32Pat => VmcsField::HostIa32Pat,
            Self::HostIa32Efer => VmcsField::HostIa32Efer,
            Self::HostIa32PerfGlobalCtrl => VmcsField::HostIa32PerfGlobalCtrl,
        }
    }

    pub fn from_vmcs_field(field: VmcsField) -> Option<Self> {
        match field {
            VmcsField::IoBitmapA => Some(Self::IoBitmapA),
            VmcsField::IoBitmapB => Some(Self::IoBitmapB),
            VmcsField::MsrBitmap => Some(Self::MsrBitmap),
            VmcsField::VmExitMsrStoreAddr => Some(Self::VmExitMsrStoreAddr),
            VmcsField::VmExitMsrLoadAddr => Some(Self::VmExitMsrLoadAddr),
            VmcsField::VmEntryMsrLoadAddr => Some(Self::VmEntryMsrLoadAddr),
            VmcsField::PmlAddress => Some(Self::PmlAddress),
            VmcsField::TscOffset => Some(Self::TscOffset),
            VmcsField::VirtualApicPageAddr => Some(Self::VirtualApicPageAddr),
            VmcsField::ApicAccessAddr => Some(Self::ApicAccessAddr),
            VmcsField::PostedIntrDescAddr => Some(Self::PostedIntrDescAddr),
            VmcsField::VmFunctionControl => Some(Self::VmFunctionControl),
            VmcsField::EptPointer => Some(Self::EptPointer),
            VmcsField::EoiExitBitmap0 => Some(Self::EoiExitBitmap0),
            VmcsField::EoiExitBitmap1 => Some(Self::EoiExitBitmap1),
            VmcsField::EoiExitBitmap2 => Some(Self::EoiExitBitmap2),
            VmcsField::EoiExitBitmap3 => Some(Self::EoiExitBitmap3),
            VmcsField::EptpListAddress => Some(Self::EptpListAddress),
            VmcsField::VmreadBitmap => Some(Self::VmreadBitmap),
            VmcsField::VmwriteBitmap => Some(Self::VmwriteBitmap),
            VmcsField::XssExitBitmap => Some(Self::XssExitBitmap),
            VmcsField::EnclsExitingBitmap => Some(Self::EnclsExitingBitmap),
            VmcsField::TscMultiplier => Some(Self::TscMultiplier),
            VmcsField::TertiaryVmExecControl => Some(Self::TertiaryVmExecControl),
            VmcsField::PidPointerTable => Some(Self::PidPointerTable),
            VmcsField::GuestPhysicalAddress => Some(Self::GuestPhysicalAddress),
            VmcsField::VmcsLinkPointer => Some(Self::VmcsLinkPointer),
            VmcsField::GuestIa32Debugctl => Some(Self::GuestIa32Debugctl),
            VmcsField::GuestIa32Pat => Some(Self::GuestIa32Pat),
            VmcsField::GuestIa32Efer => Some(Self::GuestIa32Efer),
            VmcsField::GuestIa32PerfGlobalCtrl => Some(Self::GuestIa32PerfGlobalCtrl),
            VmcsField::GuestPdptr0 => Some(Self::GuestPdptr0),
            VmcsField::GuestPdptr1 => Some(Self::GuestPdptr1),
            VmcsField::GuestPdptr2 => Some(Self::GuestPdptr2),
            VmcsField::GuestPdptr3 => Some(Self::GuestPdptr3),
            VmcsField::GuestBndcfgs => Some(Self::GuestBndcfgs),
            VmcsField::GuestIa32RtitCtl => Some(Self::GuestIa32RtitCtl),
            VmcsField::HostIa32Pat => Some(Self::HostIa32Pat),
            VmcsField::HostIa32Efer => Some(Self::HostIa32Efer),
            VmcsField::HostIa32PerfGlobalCtrl => Some(Self::HostIa32PerfGlobalCtrl),
            _ => None,
        }
    }

    pub fn from_usize(v: usize) -> Self {
        match v {
            0 => Self::IoBitmapA,
            1 => Self::IoBitmapB,
            2 => Self::MsrBitmap,
            3 => Self::VmExitMsrStoreAddr,
            4 => Self::VmExitMsrLoadAddr,
            5 => Self::VmEntryMsrLoadAddr,
            6 => Self::PmlAddress,
            7 => Self::TscOffset,
            8 => Self::VirtualApicPageAddr,
            9 => Self::ApicAccessAddr,
            10 => Self::PostedIntrDescAddr,
            11 => Self::VmFunctionControl,
            12 => Self::EptPointer,
            13 => Self::EoiExitBitmap0,
            14 => Self::EoiExitBitmap1,
            15 => Self::EoiExitBitmap2,
            16 => Self::EoiExitBitmap3,
            17 => Self::EptpListAddress,
            18 => Self::VmreadBitmap,
            19 => Self::VmwriteBitmap,
            20 => Self::XssExitBitmap,
            21 => Self::EnclsExitingBitmap,
            22 => Self::TscMultiplier,
            23 => Self::TertiaryVmExecControl,
            24 => Self::PidPointerTable,
            25 => Self::GuestPhysicalAddress,
            26 => Self::VmcsLinkPointer,
            27 => Self::GuestIa32Debugctl,
            28 => Self::GuestIa32Pat,
            29 => Self::GuestIa32Efer,
            30 => Self::GuestIa32PerfGlobalCtrl,
            31 => Self::GuestPdptr0,
            32 => Self::GuestPdptr1,
            33 => Self::GuestPdptr2,
            34 => Self::GuestPdptr3,
            35 => Self::GuestBndcfgs,
            36 => Self::GuestIa32RtitCtl,
            37 => Self::HostIa32Pat,
            38 => Self::HostIa32Efer,
            39 => Self::HostIa32PerfGlobalCtrl,
            _ => panic!("Invalid"),
        }
    }

    pub const fn size() -> usize {
        return Self::HostIa32PerfGlobalCtrl as usize + 1;
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum Context16x86 {
    VirtualProcessorId = 0,
    PostedIntrNv = 1,
    LastPidPointerIndex = 2,
    GuestEsSelector = 3,
    GuestCsSelector = 4,
    GuestSsSelector = 5,
    GuestDsSelector = 6,
    GuestFsSelector = 7,
    GuestGsSelector = 8,
    GuestLdtrSelector = 9,
    GuestTrSelector = 10,
    GuestIntrStatus = 11,
    GuestPmlIndex = 12,
    HostEsSelector = 13,
    HostCsSelector = 14,
    HostSsSelector = 15,
    HostDsSelector = 16,
    HostFsSelector = 17,
    HostGsSelector = 18,
    HostTrSelector = 19,
}

impl Context16x86 {
    pub fn as_vmcs_field(&self) -> VmcsField {
        match self {
            Self::VirtualProcessorId => VmcsField::VirtualProcessorId,
            Self::PostedIntrNv => VmcsField::PostedIntrNv,
            Self::LastPidPointerIndex => VmcsField::LastPidPointerIndex,
            Self::GuestEsSelector => VmcsField::GuestEsSelector,
            Self::GuestCsSelector => VmcsField::GuestCsSelector,
            Self::GuestSsSelector => VmcsField::GuestSsSelector,
            Self::GuestDsSelector => VmcsField::GuestDsSelector,
            Self::GuestFsSelector => VmcsField::GuestFsSelector,
            Self::GuestGsSelector => VmcsField::GuestGsSelector,
            Self::GuestLdtrSelector => VmcsField::GuestLdtrSelector,
            Self::GuestTrSelector => VmcsField::GuestTrSelector,
            Self::GuestIntrStatus => VmcsField::GuestIntrStatus,
            Self::GuestPmlIndex => VmcsField::GuestPmlIndex,
            Self::HostEsSelector => VmcsField::HostEsSelector,
            Self::HostCsSelector => VmcsField::HostCsSelector,
            Self::HostSsSelector => VmcsField::HostSsSelector,
            Self::HostDsSelector => VmcsField::HostDsSelector,
            Self::HostFsSelector => VmcsField::HostFsSelector,
            Self::HostGsSelector => VmcsField::HostGsSelector,
            Self::HostTrSelector => VmcsField::HostTrSelector,
        }
    }

    pub fn from_vmcs_field(field: VmcsField) -> Option<Self> {
        match field {
            VmcsField::VirtualProcessorId => Some(Self::VirtualProcessorId),
            VmcsField::PostedIntrNv => Some(Self::PostedIntrNv),
            VmcsField::LastPidPointerIndex => Some(Self::LastPidPointerIndex),
            VmcsField::GuestEsSelector => Some(Self::GuestEsSelector),
            VmcsField::GuestCsSelector => Some(Self::GuestCsSelector),
            VmcsField::GuestSsSelector => Some(Self::GuestSsSelector),
            VmcsField::GuestDsSelector => Some(Self::GuestDsSelector),
            VmcsField::GuestFsSelector => Some(Self::GuestFsSelector),
            VmcsField::GuestGsSelector => Some(Self::GuestGsSelector),
            VmcsField::GuestLdtrSelector => Some(Self::GuestLdtrSelector),
            VmcsField::GuestTrSelector => Some(Self::GuestTrSelector),
            VmcsField::GuestIntrStatus => Some(Self::GuestIntrStatus),
            VmcsField::GuestPmlIndex => Some(Self::GuestPmlIndex),
            VmcsField::HostEsSelector => Some(Self::HostEsSelector),
            VmcsField::HostCsSelector => Some(Self::HostCsSelector),
            VmcsField::HostSsSelector => Some(Self::HostSsSelector),
            VmcsField::HostDsSelector => Some(Self::HostDsSelector),
            VmcsField::HostFsSelector => Some(Self::HostFsSelector),
            VmcsField::HostGsSelector => Some(Self::HostGsSelector),
            VmcsField::HostTrSelector => Some(Self::HostTrSelector),
            _ => None,
        }
    }

    pub fn from_usize(v: usize) -> Self {
        match v {
            0 => Self::VirtualProcessorId,
            1 => Self::PostedIntrNv,
            2 => Self::LastPidPointerIndex,
            3 => Self::GuestEsSelector,
            4 => Self::GuestCsSelector,
            5 => Self::GuestSsSelector,
            6 => Self::GuestDsSelector,
            7 => Self::GuestFsSelector,
            8 => Self::GuestGsSelector,
            9 => Self::GuestLdtrSelector,
            10 => Self::GuestTrSelector,
            11 => Self::GuestIntrStatus,
            12 => Self::GuestPmlIndex,
            13 => Self::HostEsSelector,
            14 => Self::HostCsSelector,
            15 => Self::HostSsSelector,
            16 => Self::HostDsSelector,
            17 => Self::HostFsSelector,
            18 => Self::HostGsSelector,
            19 => Self::HostTrSelector,
            _ => panic!("Invalid"),
        }
    }

    pub const fn size() -> usize {
        return Self::HostTrSelector as usize + 1;
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum ContextNatx86 {
    Cr0GuestHostMask = 0,
    Cr4GuestHostMask = 1,
    Cr0ReadShadow = 2,
    Cr4ReadShadow = 3,
    Cr3TargetValue0 = 4,
    Cr3TargetValue1 = 5,
    Cr3TargetValue2 = 6,
    Cr3TargetValue3 = 7,
    ExitQualification = 8,
    GuestLinearAddress = 9,
    GuestCr0 = 10,
    GuestCr3 = 11,
    GuestCr4 = 12,
    GuestEsBase = 13,
    GuestCsBase = 14,
    GuestSsBase = 15,
    GuestDsBase = 16,
    GuestFsBase = 17,
    GuestGsBase = 18,
    GuestLdtrBase = 19,
    GuestTrBase = 20,
    GuestGdtrBase = 21,
    GuestIdtrBase = 22,
    GuestDr7 = 23,
    GuestRsp = 24,
    GuestRip = 25,
    GuestRflags = 26,
    GuestPendingDbgExceptions = 27,
    GuestSysenterEsp = 28,
    GuestSysenterEip = 29,
}

impl ContextNatx86 {
    pub fn as_vmcs_field(&self) -> VmcsField {
        match self {
            Self::Cr0GuestHostMask => VmcsField::Cr0GuestHostMask,
            Self::Cr4GuestHostMask => VmcsField::Cr4GuestHostMask,
            Self::Cr0ReadShadow => VmcsField::Cr0ReadShadow,
            Self::Cr4ReadShadow => VmcsField::Cr4ReadShadow,
            Self::Cr3TargetValue0 => VmcsField::Cr3TargetValue0,
            Self::Cr3TargetValue1 => VmcsField::Cr3TargetValue1,
            Self::Cr3TargetValue2 => VmcsField::Cr3TargetValue2,
            Self::Cr3TargetValue3 => VmcsField::Cr3TargetValue3,
            Self::ExitQualification => VmcsField::ExitQualification,
            Self::GuestLinearAddress => VmcsField::GuestLinearAddress,
            Self::GuestCr0 => VmcsField::GuestCr0,
            Self::GuestCr3 => VmcsField::GuestCr3,
            Self::GuestCr4 => VmcsField::GuestCr4,
            Self::GuestEsBase => VmcsField::GuestEsBase,
            Self::GuestCsBase => VmcsField::GuestCsBase,
            Self::GuestSsBase => VmcsField::GuestSsBase,
            Self::GuestDsBase => VmcsField::GuestDsBase,
            Self::GuestFsBase => VmcsField::GuestFsBase,
            Self::GuestGsBase => VmcsField::GuestGsBase,
            Self::GuestLdtrBase => VmcsField::GuestLdtrBase,
            Self::GuestTrBase => VmcsField::GuestTrBase,
            Self::GuestGdtrBase => VmcsField::GuestGdtrBase,
            Self::GuestIdtrBase => VmcsField::GuestIdtrBase,
            Self::GuestDr7 => VmcsField::GuestDr7,
            Self::GuestRsp => VmcsField::GuestRsp,
            Self::GuestRip => VmcsField::GuestRip,
            Self::GuestRflags => VmcsField::GuestRflags,
            Self::GuestPendingDbgExceptions => VmcsField::GuestPendingDbgExceptions,
            Self::GuestSysenterEsp => VmcsField::GuestSysenterEsp,
            Self::GuestSysenterEip => VmcsField::GuestSysenterEip,
        }
    }

    pub fn from_vmcs_field(field: VmcsField) -> Option<Self> {
        match field {
            VmcsField::Cr0GuestHostMask => Some(Self::Cr0GuestHostMask),
            VmcsField::Cr4GuestHostMask => Some(Self::Cr4GuestHostMask),
            VmcsField::Cr0ReadShadow => Some(Self::Cr0ReadShadow),
            VmcsField::Cr4ReadShadow => Some(Self::Cr4ReadShadow),
            VmcsField::Cr3TargetValue0 => Some(Self::Cr3TargetValue0),
            VmcsField::Cr3TargetValue1 => Some(Self::Cr3TargetValue1),
            VmcsField::Cr3TargetValue2 => Some(Self::Cr3TargetValue2),
            VmcsField::Cr3TargetValue3 => Some(Self::Cr3TargetValue3),
            VmcsField::ExitQualification => Some(Self::ExitQualification),
            VmcsField::GuestLinearAddress => Some(Self::GuestLinearAddress),
            VmcsField::GuestCr0 => Some(Self::GuestCr0),
            VmcsField::GuestCr3 => Some(Self::GuestCr3),
            VmcsField::GuestCr4 => Some(Self::GuestCr4),
            VmcsField::GuestEsBase => Some(Self::GuestEsBase),
            VmcsField::GuestCsBase => Some(Self::GuestCsBase),
            VmcsField::GuestSsBase => Some(Self::GuestSsBase),
            VmcsField::GuestDsBase => Some(Self::GuestDsBase),
            VmcsField::GuestFsBase => Some(Self::GuestFsBase),
            VmcsField::GuestGsBase => Some(Self::GuestGsBase),
            VmcsField::GuestLdtrBase => Some(Self::GuestLdtrBase),
            VmcsField::GuestTrBase => Some(Self::GuestTrBase),
            VmcsField::GuestGdtrBase => Some(Self::GuestGdtrBase),
            VmcsField::GuestIdtrBase => Some(Self::GuestIdtrBase),
            VmcsField::GuestDr7 => Some(Self::GuestDr7),
            VmcsField::GuestRsp => Some(Self::GuestRsp),
            VmcsField::GuestRip => Some(Self::GuestRip),
            VmcsField::GuestRflags => Some(Self::GuestRflags),
            VmcsField::GuestPendingDbgExceptions => Some(Self::GuestPendingDbgExceptions),
            VmcsField::GuestSysenterEsp => Some(Self::GuestSysenterEsp),
            VmcsField::GuestSysenterEip => Some(Self::GuestSysenterEip),
            _ => None,
        }
    }

    pub fn from_usize(v: usize) -> Self {
        match v {
            0 => Self::Cr0GuestHostMask,
            1 => Self::Cr4GuestHostMask,
            2 => Self::Cr0ReadShadow,
            3 => Self::Cr4ReadShadow,
            4 => Self::Cr3TargetValue0,
            5 => Self::Cr3TargetValue1,
            6 => Self::Cr3TargetValue2,
            7 => Self::Cr3TargetValue3,
            8 => Self::ExitQualification,
            9 => Self::GuestLinearAddress,
            10 => Self::GuestCr0,
            11 => Self::GuestCr3,
            12 => Self::GuestCr4,
            13 => Self::GuestEsBase,
            14 => Self::GuestCsBase,
            15 => Self::GuestSsBase,
            16 => Self::GuestDsBase,
            17 => Self::GuestFsBase,
            18 => Self::GuestGsBase,
            19 => Self::GuestLdtrBase,
            20 => Self::GuestTrBase,
            21 => Self::GuestGdtrBase,
            22 => Self::GuestIdtrBase,
            23 => Self::GuestDr7,
            24 => Self::GuestRsp,
            25 => Self::GuestRip,
            26 => Self::GuestRflags,
            27 => Self::GuestPendingDbgExceptions,
            28 => Self::GuestSysenterEsp,
            29 => Self::GuestSysenterEip,
            _ => panic!("Invalid {}", v),
        }
    }

    pub const fn size() -> usize {
        return Self::GuestSysenterEip as usize + 1;
    }
}

pub const DUMP_FRAME: [(VmcsField, VmcsField); 9] = [
    (VmcsField::GuestRbx, VmcsField::GuestRip),
    (VmcsField::GuestRcx, VmcsField::GuestRsp),
    (VmcsField::GuestRdx, VmcsField::GuestRflags),
    (VmcsField::GuestRsi, VmcsField::VmInstructionError),
    (VmcsField::GuestR8, VmcsField::VmExitReason),
    (VmcsField::GuestR9, VmcsField::VmExitIntrInfo),
    (VmcsField::GuestR10, VmcsField::VmExitIntrErrorCode),
    (VmcsField::GuestR11, VmcsField::VmExitInstructionLen),
    (VmcsField::GuestR12, VmcsField::VmInstructionError),
];

/// Scheduling information.
pub struct SchedInfo {
    pub timed: bool,
    pub budget: usize,
    pub saved_ctrls: usize,
}

pub struct CpuidEntry {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

pub struct Contextx86 {
    pub regs: RegisterContext<
        { Context16x86::size() },
        { Context32x86::size() },
        { Context64x86::size() },
        { ContextNatx86::size() },
        { ContextGpx86::size() },
    >,
    // State.
    pub interrupted: bool,
    pub sched_info: SchedInfo,
    pub vmcs: Handle<RCFrame>,
    pub launched: bool,
    pub nb_active_cpuid_entries: usize,
    pub cpuid_entries: [CpuidEntry; MAX_CPUID_ENTRIES],
}

impl Contextx86 {
    pub fn translate_field(field: VmcsField) -> (RegisterGroup, usize) {
        match (field.width(), field.is_gp_register()) {
            (_, true) => (
                RegisterGroup::RegGp,
                ContextGpx86::from_vmcs_field(field).unwrap() as usize,
            ),

            (VmcsFieldWidth::Width16, _) => (
                RegisterGroup::Reg16,
                Context16x86::from_vmcs_field(field).unwrap() as usize,
            ),
            (VmcsFieldWidth::Width32, _) => (
                RegisterGroup::Reg32,
                Context32x86::from_vmcs_field(field).unwrap() as usize,
            ),
            (VmcsFieldWidth::Width64, _) => (
                RegisterGroup::Reg64,
                Context64x86::from_vmcs_field(field).unwrap() as usize,
            ),
            (VmcsFieldWidth::WidthNat, _) => (
                RegisterGroup::RegNat,
                ContextNatx86::from_vmcs_field(field).unwrap() as usize,
            ),
        }
    }

    pub fn set(
        &mut self,
        field: VmcsField,
        value: usize,
        vcpu: Option<&mut ActiveVmcs>,
    ) -> Result<(), VmxError> {
        let (group, idx) = Self::translate_field(field);
        self.regs.set(group, idx, value).unwrap();
        if group == RegisterGroup::RegGp {
            self.regs.clear(group, idx);
        } else if let Some(vcpu) = vcpu {
            vcpu.set(field, value)?;
            self.regs.clear(group, idx);
        }
        Ok(())
    }

    pub fn get_current(
        &mut self,
        field: VmcsField,
        vcpu: Option<&ActiveVmcs>,
    ) -> Result<usize, VmxError> {
        let (group, idx) = Self::translate_field(field);
        if group != RegisterGroup::RegGp {
            if let Some(vcpu) = vcpu {
                self.regs.set(group, idx, vcpu.get(field)?).unwrap();
                self.regs.clear(group, idx);
            }
        }
        Ok(self.regs.get(group, idx).unwrap())
    }

    //TODO: modify this.
    pub fn get_from_frame(
        &mut self,
        field: VmcsField,
        vcpu: &ActiveVmcs,
    ) -> Result<usize, VmxError> {
        let (group, idx) = Self::translate_field(field);
        if group != RegisterGroup::RegGp {
            self.regs.set(group, idx, vcpu.get(field)?).unwrap();
            self.regs.clear(group, idx);
        }
        Ok(self.regs.get(group, idx).unwrap())
    }

    /// Read context, write vcpu.
    pub fn flush(&mut self, vcpu: &mut ActiveVmcs) {
        let update = |g: RegisterGroup, idx: usize, value: usize| {
            let field = match g {
                RegisterGroup::Reg16 => Context16x86::from_usize(idx).as_vmcs_field(),
                RegisterGroup::Reg32 => Context32x86::from_usize(idx).as_vmcs_field(),
                RegisterGroup::Reg64 => Context64x86::from_usize(idx).as_vmcs_field(),
                RegisterGroup::RegNat => ContextNatx86::from_usize(idx).as_vmcs_field(),
                RegisterGroup::RegGp => ContextGpx86::from_usize(idx).as_vmcs_field(),
            };
            if field.is_gp_register() {
                return;
            }
            match field {
                VmcsField::PinBasedVmExecControl => {
                    vcpu.set_pin_based_ctrls(PinbasedControls::from_bits_truncate(value as u32))
                        .unwrap();
                }
                VmcsField::CpuBasedVmExecControl => {
                    vcpu.set_primary_ctrls(PrimaryControls::from_bits_truncate(value as u32))
                        .unwrap();
                }
                VmcsField::SecondaryVmExecControl => {
                    vcpu.set_secondary_ctrls(SecondaryControls::from_bits_truncate(value as u32))
                        .unwrap();
                }
                _ => {
                    vcpu.set(field, value).unwrap();
                }
            }
        };
        self.regs.flush(update);
    }

    /// Read vcpu, write context.
    pub fn _load(&mut self, vcpu: &ActiveVmcs) {
        // General purpose registers are handled by vmlaunch/vmresume.
        // 16-bits.
        for i in 0..Context16x86::size() {
            self.regs.state_16.values[i] = vcpu
                .get(Context16x86::from_usize(i).as_vmcs_field())
                .unwrap_or(0);
        }

        // 32-bits.
        for i in 0..Context32x86::size() {
            self.regs.state_32.values[i] = vcpu
                .get(Context32x86::from_usize(i).as_vmcs_field())
                .unwrap_or(0);
        }

        // 64-bits.
        for i in 0..Context64x86::size() {
            self.regs.state_64.values[i] = vcpu
                .get(Context64x86::from_usize(i).as_vmcs_field())
                .unwrap_or(0);
        }

        // Nat-bits.
        for i in 0..ContextNatx86::size() {
            self.regs.state_nat.values[i] = vcpu
                .get(ContextNatx86::from_usize(i).as_vmcs_field())
                .unwrap_or(0);
        }
    }

    /// Switch frames and flush.
    pub fn _switch_flush(&mut self, rc_vmcs: &Mutex<RCFramePool>, vcpu: &mut ActiveVmcs) {
        let locked = rc_vmcs.lock();
        let rc_frame = locked.get(self.vmcs).unwrap();
        // Switch the frame.
        vcpu.switch_frame(rc_frame.frame).unwrap();
        // Load values that changed.
        self.flush(vcpu);
    }

    pub fn switch_no_flush(&mut self, rc_vmcs: &Mutex<RCFramePool>, vcpu: &mut ActiveVmcs) {
        let locked = rc_vmcs.lock();
        let rc_frame = locked.get(self.vmcs).unwrap();
        // Switch the frame.
        vcpu.switch_frame(rc_frame.frame).unwrap();
    }

    // TODO: maybe more efficient if we dump the frame first?
    pub fn copy_interrupt_frame(
        &mut self,
        child: &mut Self,
        vcpu: &ActiveVmcs,
    ) -> Result<(), VmxError> {
        for i in DUMP_FRAME {
            let value = child.get_current(i.1, Some(vcpu))?;
            self.set(i.0, value, None)?;
        }

        Ok(())
    }

    pub fn reset(&mut self) {
        self.regs.reset();
        self.launched = false;
        self.interrupted = false;
        self.sched_info.timed = false;
        self.sched_info.saved_ctrls = 0;
        self.sched_info.budget = 0;
        //TODO: the rvmcs is cleaned elsewhere... change this.
    }
}

// Partial print of a context for general purpose registers.
// TODO: make it the default way to print things.
impl core::fmt::Debug for Contextx86 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "GP Registers {{")?;
        for i in 0..ContextGpx86::size() {
            writeln!(
                f,
                "   {:?}: {:#x}",
                ContextGpx86::from_usize(i),
                self.regs.state_gp.values[i]
            )?;
        }
        writeln!(f, "}}")?;
        Ok(())
    }
}
