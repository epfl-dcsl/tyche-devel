use crate::msr::VMX_VMCS_ENUM;
use crate::{raw, VmxError};

// ———————————————————————— Masks from Intel Manual ————————————————————————— //
// All these are defined in table 25-21 of chapter 25.11.2 in the Intel Manual.
// (VMREAD, VMWRITE, and Encodings of VMCS Fields)
// VMCS Shifts.
pub const VMCS_FIELD_ACCESS_TYPE_SHIFT: u32 = 0;
pub const VMCS_FIELD_INDEX_SHIFT: u32 = 1;
pub const VMCS_FIELD_TYPE_SHIFT: u32 = 10;
pub const VMCS_FIELD_RESERVED_LOW_SHIFT: u32 = 12;
pub const VMCS_FIELD_WIDTH_SHIFT: u32 = 13;
pub const VMCS_FIELD_RESERVED_HIGH_SHIFT: u32 = 15;
// VMCS Masks.
pub const VMCS_FIELD_ACCESS_TYPE_MASK: u32 = 1 << VMCS_FIELD_ACCESS_TYPE_SHIFT;
pub const VMCS_FIELD_INDEX_MASK: u32 = (0b111_111_111) << VMCS_FIELD_INDEX_SHIFT;
pub const VMCS_FIELD_TYPE_MASK: u32 = (0b11) << VMCS_FIELD_TYPE_SHIFT;
pub const VMCS_FIELD_RESERVED_LOW_MASK: u32 = 1 << VMCS_FIELD_RESERVED_LOW_SHIFT;
pub const VMCS_FIELD_WIDTH_MASK: u32 = (0b11) << VMCS_FIELD_WIDTH_SHIFT;
pub const VMCS_FIELD_RESERVED_HIGH_MASK: u32 =
    (0b11111_11111_11111_11) << VMCS_FIELD_RESERVED_HIGH_SHIFT;

// ———————————————————————————— Enum for Fields ————————————————————————————— //
/// VMCS Fields taken from linux/arch/x86/include/asm/vmx.h
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum VmcsField {
    VirtualProcessorId = 0x00000000,
    PostedIntrNv = 0x00000002,
    LastPidPointerIndex = 0x00000008,
    GuestEsSelector = 0x00000800,
    GuestCsSelector = 0x00000802,
    GuestSsSelector = 0x00000804,
    GuestDsSelector = 0x00000806,
    GuestFsSelector = 0x00000808,
    GuestGsSelector = 0x0000080a,
    GuestLdtrSelector = 0x0000080c,
    GuestTrSelector = 0x0000080e,
    GuestIntrStatus = 0x00000810,
    GuestPmlIndex = 0x00000812,
    HostEsSelector = 0x00000c00,
    HostCsSelector = 0x00000c02,
    HostSsSelector = 0x00000c04,
    HostDsSelector = 0x00000c06,
    HostFsSelector = 0x00000c08,
    HostGsSelector = 0x00000c0a,
    HostTrSelector = 0x00000c0c,
    IoBitmapA = 0x00002000,
    IoBitmapAHigh = 0x00002001,
    IoBitmapB = 0x00002002,
    IoBitmapBHigh = 0x00002003,
    MsrBitmap = 0x00002004,
    MsrBitmapHigh = 0x00002005,
    VmExitMsrStoreAddr = 0x00002006,
    VmExitMsrStoreAddrHigh = 0x00002007,
    VmExitMsrLoadAddr = 0x00002008,
    VMExitMsrLoadAddrHigh = 0x00002009,
    VmEntryMsrLoadAddr = 0x0000200a,
    VmEntryMsrLoadAddrHigh = 0x0000200b,
    PmlAddress = 0x0000200e,
    PmlAddressHigh = 0x0000200f,
    TscOffset = 0x00002010,
    TscOffsetHigh = 0x00002011,
    VirtualApicPageAddr = 0x00002012,
    VirtualApicPageAddrHigh = 0x00002013,
    ApicAccessAddr = 0x00002014,
    ApicAccessAddrHigh = 0x00002015,
    PostedIntrDescAddr = 0x00002016,
    PostedIntrDescAddrHigh = 0x00002017,
    VmFunctionControl = 0x00002018,
    VmFunctionControlHigh = 0x00002019,
    EptPointer = 0x0000201a,
    EptPointerHigh = 0x0000201b,
    EoiExitBitmap0 = 0x0000201c,
    EoiExitBitmap0High = 0x0000201d,
    EoiExitBitmap1 = 0x0000201e,
    EoiExitBitmap1High = 0x0000201f,
    EoiExitBitmap2 = 0x00002020,
    EoiExitBitmap2High = 0x00002021,
    EoiExitBitmap3 = 0x00002022,
    EoiExitBitmap3High = 0x00002023,
    EptpListAddress = 0x00002024,
    EptpListAddressHigh = 0x00002025,
    VmreadBitmap = 0x00002026,
    VmreadBitmapHigh = 0x00002027,
    VmwriteBitmap = 0x00002028,
    VmwriteBitmapHigh = 0x00002029,
    XssExitBitmap = 0x0000202C,
    XssExitBitmapHigh = 0x0000202D,
    EnclsExitingBitmap = 0x0000202E,
    EnclsExitingBitmapHigh = 0x0000202F,
    TscMultiplier = 0x00002032,
    TscMultiplierHigh = 0x00002033,
    TertiaryVmExecControl = 0x00002034,
    TertiaryVmExecControlHigh = 0x00002035,
    PidPointerTable = 0x00002042,
    PidPointerTableHigh = 0x00002043,
    GuestPhysicalAddress = 0x00002400,
    GuestPhysicalAddressHigh = 0x00002401,
    VmcsLinkPointer = 0x00002800,
    VmcsLinkPointerHigh = 0x00002801,
    GuestIa32Debugctl = 0x00002802,
    GuestIa32DebugctlHigh = 0x00002803,
    GuestIa32Pat = 0x00002804,
    GuestIa32PatHigh = 0x00002805,
    GuestIa32Efer = 0x00002806,
    GuestIa32EferHigh = 0x00002807,
    GuestIa32PerfGlobalCtrl = 0x00002808,
    GuestIa32PerfGlobalCtrlHigh = 0x00002809,
    GuestPdptr0 = 0x0000280a,
    GuestPdprt0High = 0x0000280b,
    GuestPdptr1 = 0x0000280c,
    GuestPdptr1High = 0x0000280d,
    GuestPdptr2 = 0x0000280e,
    GuestPdptr2High = 0x0000280f,
    GuestPdptr3 = 0x00002810,
    GuestPdptr3High = 0x00002811,
    GuestBndcfgs = 0x00002812,
    GuestBndcfgsHigh = 0x00002813,
    GuestIa32RtitCtl = 0x00002814,
    GuestIa32RtitCtlHigh = 0x00002815,
    HostIa32Pat = 0x00002c00,
    HostIa32PatHigh = 0x00002c01,
    HostIa32Efer = 0x00002c02,
    HostIa32EferHigh = 0x00002c03,
    HostIa32PerfGlobalCtrl = 0x00002c04,
    HostIa32PerfGlobalCtrlHigh = 0x00002c05,
    PinBasedVmExecControl = 0x00004000,
    CpuBasedVmExecControl = 0x00004002,
    ExceptionBitmap = 0x00004004,
    PageFaultErrorCodeMask = 0x00004006,
    PageFaultErrorCodeMatch = 0x00004008,
    Cr3TargetCount = 0x0000400a,
    VmExitControls = 0x0000400c,
    VmExitMsrStoreCount = 0x0000400e,
    VmExitMsrLoadCount = 0x00004010,
    VmEntryControls = 0x00004012,
    VmEntryMsrLoadCount = 0x00004014,
    VmEntryIntrInfoField = 0x00004016,
    VmEntryExceptionErrorCode = 0x00004018,
    VmEntryInstructionLen = 0x0000401a,
    TprThreshold = 0x0000401c,
    SecondaryVmExecControl = 0x0000401e,
    PleGap = 0x00004020,
    PleWindow = 0x00004022,
    NotifyWindow = 0x00004024,
    VmInstructionError = 0x00004400,
    VmExitReason = 0x00004402,
    VmExitIntrInfo = 0x00004404,
    VmExitIntrErrorCode = 0x00004406,
    IdtVectoringInfoField = 0x00004408,
    IdtVectoringErrorCode = 0x0000440a,
    VmExitInstructionLen = 0x0000440c,
    VmxInstructionInfo = 0x0000440e,
    GuestEsLimit = 0x00004800,
    GuestCsLimit = 0x00004802,
    GuestSsLimit = 0x00004804,
    GuestDsLimit = 0x00004806,
    GuestFsLimit = 0x00004808,
    GuestGsLimit = 0x0000480a,
    GuestLdtrLimit = 0x0000480c,
    GuestTrLimit = 0x0000480e,
    GuestGdtrLimit = 0x00004810,
    GuestIdtrLimit = 0x00004812,
    GuestEsArBytes = 0x00004814,
    GuestCsArBytes = 0x00004816,
    GuestSsArBytes = 0x00004818,
    GuestDsArBytes = 0x0000481a,
    GuestFsArBytes = 0x0000481c,
    GuestGsArBytes = 0x0000481e,
    GuestLdtrArBytes = 0x00004820,
    GuestTrArBytes = 0x00004822,
    GuestInterruptibilityInfo = 0x00004824,
    GuestActivityState = 0x00004826,
    GuestSysenterCs = 0x0000482A,
    VmxPreemptionTimerValue = 0x0000482E,
    HostIa32SysenterCs = 0x00004c00,
    Cr0GuestHostMask = 0x00006000,
    Cr4GuestHostMask = 0x00006002,
    Cr0ReadShadow = 0x00006004,
    Cr4ReadShadow = 0x00006006,
    Cr3TargetValue0 = 0x00006008,
    Cr3TargetValue1 = 0x0000600a,
    Cr3TargetValue2 = 0x0000600c,
    Cr3TargetValue3 = 0x0000600e,
    ExitQualification = 0x00006400,
    GuestLinearAddress = 0x0000640a,
    GuestCr0 = 0x00006800,
    GuestCr3 = 0x00006802,
    GuestCr4 = 0x00006804,
    GuestEsBase = 0x00006806,
    GuestCsBase = 0x00006808,
    GuestSsBase = 0x0000680a,
    GuestDsBase = 0x0000680c,
    GuestFsBase = 0x0000680e,
    GuestGsBase = 0x00006810,
    GuestLdtrBase = 0x00006812,
    GuestTrBase = 0x00006814,
    GuestGdtrBase = 0x00006816,
    GuestIdtrBase = 0x00006818,
    GuestDr7 = 0x0000681a,
    GuestRsp = 0x0000681c,
    GuestRip = 0x0000681e,
    GuestRflags = 0x00006820,
    GuestPendingDbgExceptions = 0x00006822,
    GuestSysenterEsp = 0x00006824,
    GuestSysenterEip = 0x00006826,
    HostCr0 = 0x00006c00,
    HostCr3 = 0x00006c02,
    HostCr4 = 0x00006c04,
    HostFsBase = 0x00006c06,
    HostGsBase = 0x00006c08,
    HostTrBase = 0x00006c0a,
    HostGdtrBase = 0x00006c0c,
    HostIdtrBase = 0x00006c0e,
    HostIa32SysenterEsp = 0x00006c10,
    HostIa32SysenterEip = 0x00006c12,
    HostRsp = 0x00006c14,
    HostRip = 0x00006c16,
    /*Invalid Vmcs values representing general purpose registers.*/
    GuestRax = 0xff007000,
    GuestRbx = 0xff007002,
    GuestRcx = 0xff007004,
    GuestRdx = 0xff007006,
    GuestRbp = 0xff007008,
    GuestRsi = 0xff00700a,
    GuestRdi = 0xff00700c,
    GuestR8 = 0xff00700e,
    GuestR9 = 0xff007010,
    GuestR10 = 0xff007012,
    GuestR11 = 0xff007014,
    GuestR12 = 0xff007016,
    GuestR13 = 0xff007018,
    GuestR14 = 0xff00701a,
    GuestR15 = 0xff00701c,
    GuestLstar = 0xff00701e,
}

/// Valid VmcsFieldAccessType as encoded in a VMCS.
/// See chapter 25.11.2 and table 25-21 in the Intel manual.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum VmcsFieldAccessType {
    Full = 0,
    High = 1,
}

impl VmcsFieldAccessType {
    pub fn from_raw(v: u8) -> VmcsFieldAccessType {
        match v {
            0 => VmcsFieldAccessType::Full,
            1 => VmcsFieldAccessType::High,
            _ => panic!("Invalid VMCS Access type."),
        }
    }
}

/// Valid VmcsFieldWidth as encoded in a VMCS.
/// See chapter 25.11.2 and table 25-21 in the Intel manual.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum VmcsFieldWidth {
    Width16 = 0,
    Width32 = 1,
    Width64 = 2,
    WidthNat = 3,
}

impl VmcsFieldWidth {
    pub fn from_raw(v: u8) -> VmcsFieldWidth {
        match v {
            0 => VmcsFieldWidth::Width16,
            1 => VmcsFieldWidth::Width32,
            2 => VmcsFieldWidth::Width64,
            3 => VmcsFieldWidth::WidthNat,
            _ => panic!("Invalid VMCS field width value"),
        }
    }
}

/// Types of VMCSFields.
/// See Chapter 25.11.2 table 25-21 in the Intel manual.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum VmcsFieldType {
    Control = 0,
    VmExitInformation = 1,
    GuestState = 2,
    HostState = 3,
    GuestGP = 4,
}

impl VmcsFieldType {
    pub fn from_raw(v: u8) -> VmcsFieldType {
        match v {
            0 => VmcsFieldType::Control,
            1 => VmcsFieldType::VmExitInformation,
            2 => VmcsFieldType::GuestState,
            3 => VmcsFieldType::HostState,
            // This is not in the Vmcs!
            4 => VmcsFieldType::GuestGP,
            _ => panic!("Invalid VMCS field type value"),
        }
    }

    pub fn is_vmwritable(&self) -> bool {
        match *self {
            VmcsFieldType::VmExitInformation => false,
            // GuestGP is not writable via vmwrite.
            VmcsFieldType::GuestGP => false,
            _ => true,
        }
    }
}

impl VmcsField {
    /// Convert an u32 into a VmcsField.
    /// Returns Some(VmcsField) if it is a valid value, None otherwise.
    pub fn from_u32(v: u32) -> Option<VmcsField> {
        match v {
            0x00000000 => Some(VmcsField::VirtualProcessorId),
            0x00000002 => Some(VmcsField::PostedIntrNv),
            0x00000008 => Some(VmcsField::LastPidPointerIndex),
            0x00000800 => Some(VmcsField::GuestEsSelector),
            0x00000802 => Some(VmcsField::GuestCsSelector),
            0x00000804 => Some(VmcsField::GuestSsSelector),
            0x00000806 => Some(VmcsField::GuestDsSelector),
            0x00000808 => Some(VmcsField::GuestFsSelector),
            0x0000080a => Some(VmcsField::GuestGsSelector),
            0x0000080c => Some(VmcsField::GuestLdtrSelector),
            0x0000080e => Some(VmcsField::GuestTrSelector),
            0x00000810 => Some(VmcsField::GuestIntrStatus),
            0x00000812 => Some(VmcsField::GuestPmlIndex),
            0x00000c00 => Some(VmcsField::HostEsSelector),
            0x00000c02 => Some(VmcsField::HostCsSelector),
            0x00000c04 => Some(VmcsField::HostSsSelector),
            0x00000c06 => Some(VmcsField::HostDsSelector),
            0x00000c08 => Some(VmcsField::HostFsSelector),
            0x00000c0a => Some(VmcsField::HostGsSelector),
            0x00000c0c => Some(VmcsField::HostTrSelector),
            0x00002000 => Some(VmcsField::IoBitmapA),
            0x00002001 => Some(VmcsField::IoBitmapAHigh),
            0x00002002 => Some(VmcsField::IoBitmapB),
            0x00002003 => Some(VmcsField::IoBitmapBHigh),
            0x00002004 => Some(VmcsField::MsrBitmap),
            0x00002005 => Some(VmcsField::MsrBitmapHigh),
            0x00002006 => Some(VmcsField::VmExitMsrStoreAddr),
            0x00002007 => Some(VmcsField::VmExitMsrStoreAddrHigh),
            0x00002008 => Some(VmcsField::VmExitMsrLoadAddr),
            0x00002009 => Some(VmcsField::VMExitMsrLoadAddrHigh),
            0x0000200a => Some(VmcsField::VmEntryMsrLoadAddr),
            0x0000200b => Some(VmcsField::VmEntryMsrLoadAddrHigh),
            0x0000200e => Some(VmcsField::PmlAddress),
            0x0000200f => Some(VmcsField::PmlAddressHigh),
            0x00002010 => Some(VmcsField::TscOffset),
            0x00002011 => Some(VmcsField::TscOffsetHigh),
            0x00002012 => Some(VmcsField::VirtualApicPageAddr),
            0x00002013 => Some(VmcsField::VirtualApicPageAddrHigh),
            0x00002014 => Some(VmcsField::ApicAccessAddr),
            0x00002015 => Some(VmcsField::ApicAccessAddrHigh),
            0x00002016 => Some(VmcsField::PostedIntrDescAddr),
            0x00002017 => Some(VmcsField::PostedIntrDescAddrHigh),
            0x00002018 => Some(VmcsField::VmFunctionControl),
            0x00002019 => Some(VmcsField::VmFunctionControlHigh),
            0x0000201a => Some(VmcsField::EptPointer),
            0x0000201b => Some(VmcsField::EptPointerHigh),
            0x0000201c => Some(VmcsField::EoiExitBitmap0),
            0x0000201d => Some(VmcsField::EoiExitBitmap0High),
            0x0000201e => Some(VmcsField::EoiExitBitmap1),
            0x0000201f => Some(VmcsField::EoiExitBitmap1High),
            0x00002020 => Some(VmcsField::EoiExitBitmap2),
            0x00002021 => Some(VmcsField::EoiExitBitmap2High),
            0x00002022 => Some(VmcsField::EoiExitBitmap3),
            0x00002023 => Some(VmcsField::EoiExitBitmap3High),
            0x00002024 => Some(VmcsField::EptpListAddress),
            0x00002025 => Some(VmcsField::EptpListAddressHigh),
            0x00002026 => Some(VmcsField::VmreadBitmap),
            0x00002027 => Some(VmcsField::VmreadBitmapHigh),
            0x00002028 => Some(VmcsField::VmwriteBitmap),
            0x00002029 => Some(VmcsField::VmwriteBitmapHigh),
            0x0000202C => Some(VmcsField::XssExitBitmap),
            0x0000202D => Some(VmcsField::XssExitBitmapHigh),
            0x0000202E => Some(VmcsField::EnclsExitingBitmap),
            0x0000202F => Some(VmcsField::EnclsExitingBitmapHigh),
            0x00002032 => Some(VmcsField::TscMultiplier),
            0x00002033 => Some(VmcsField::TscMultiplierHigh),
            0x00002034 => Some(VmcsField::TertiaryVmExecControl),
            0x00002035 => Some(VmcsField::TertiaryVmExecControlHigh),
            0x00002042 => Some(VmcsField::PidPointerTable),
            0x00002043 => Some(VmcsField::PidPointerTableHigh),
            0x00002400 => Some(VmcsField::GuestPhysicalAddress),
            0x00002401 => Some(VmcsField::GuestPhysicalAddressHigh),
            0x00002800 => Some(VmcsField::VmcsLinkPointer),
            0x00002801 => Some(VmcsField::VmcsLinkPointerHigh),
            0x00002802 => Some(VmcsField::GuestIa32Debugctl),
            0x00002803 => Some(VmcsField::GuestIa32DebugctlHigh),
            0x00002804 => Some(VmcsField::GuestIa32Pat),
            0x00002805 => Some(VmcsField::GuestIa32PatHigh),
            0x00002806 => Some(VmcsField::GuestIa32Efer),
            0x00002807 => Some(VmcsField::GuestIa32EferHigh),
            0x00002808 => Some(VmcsField::GuestIa32PerfGlobalCtrl),
            0x00002809 => Some(VmcsField::GuestIa32PerfGlobalCtrlHigh),
            0x0000280a => Some(VmcsField::GuestPdptr0),
            0x0000280b => Some(VmcsField::GuestPdprt0High),
            0x0000280c => Some(VmcsField::GuestPdptr1),
            0x0000280d => Some(VmcsField::GuestPdptr1High),
            0x0000280e => Some(VmcsField::GuestPdptr2),
            0x0000280f => Some(VmcsField::GuestPdptr2High),
            0x00002810 => Some(VmcsField::GuestPdptr3),
            0x00002811 => Some(VmcsField::GuestPdptr3High),
            0x00002812 => Some(VmcsField::GuestBndcfgs),
            0x00002813 => Some(VmcsField::GuestBndcfgsHigh),
            0x00002814 => Some(VmcsField::GuestIa32RtitCtl),
            0x00002815 => Some(VmcsField::GuestIa32RtitCtlHigh),
            0x00002c00 => Some(VmcsField::HostIa32Pat),
            0x00002c01 => Some(VmcsField::HostIa32PatHigh),
            0x00002c02 => Some(VmcsField::HostIa32Efer),
            0x00002c03 => Some(VmcsField::HostIa32EferHigh),
            0x00002c04 => Some(VmcsField::HostIa32PerfGlobalCtrl),
            0x00002c05 => Some(VmcsField::HostIa32PerfGlobalCtrlHigh),
            0x00004000 => Some(VmcsField::PinBasedVmExecControl),
            0x00004002 => Some(VmcsField::CpuBasedVmExecControl),
            0x00004004 => Some(VmcsField::ExceptionBitmap),
            0x00004006 => Some(VmcsField::PageFaultErrorCodeMask),
            0x00004008 => Some(VmcsField::PageFaultErrorCodeMatch),
            0x0000400a => Some(VmcsField::Cr3TargetCount),
            0x0000400c => Some(VmcsField::VmExitControls),
            0x0000400e => Some(VmcsField::VmExitMsrStoreCount),
            0x00004010 => Some(VmcsField::VmExitMsrLoadCount),
            0x00004012 => Some(VmcsField::VmEntryControls),
            0x00004014 => Some(VmcsField::VmEntryMsrLoadCount),
            0x00004016 => Some(VmcsField::VmEntryIntrInfoField),
            0x00004018 => Some(VmcsField::VmEntryExceptionErrorCode),
            0x0000401a => Some(VmcsField::VmEntryInstructionLen),
            0x0000401c => Some(VmcsField::TprThreshold),
            0x0000401e => Some(VmcsField::SecondaryVmExecControl),
            0x00004020 => Some(VmcsField::PleGap),
            0x00004022 => Some(VmcsField::PleWindow),
            0x00004024 => Some(VmcsField::NotifyWindow),
            0x00004400 => Some(VmcsField::VmInstructionError),
            0x00004402 => Some(VmcsField::VmExitReason),
            0x00004404 => Some(VmcsField::VmExitIntrInfo),
            0x00004406 => Some(VmcsField::VmExitIntrErrorCode),
            0x00004408 => Some(VmcsField::IdtVectoringInfoField),
            0x0000440a => Some(VmcsField::IdtVectoringErrorCode),
            0x0000440c => Some(VmcsField::VmExitInstructionLen),
            0x0000440e => Some(VmcsField::VmxInstructionInfo),
            0x00004800 => Some(VmcsField::GuestEsLimit),
            0x00004802 => Some(VmcsField::GuestCsLimit),
            0x00004804 => Some(VmcsField::GuestSsLimit),
            0x00004806 => Some(VmcsField::GuestDsLimit),
            0x00004808 => Some(VmcsField::GuestFsLimit),
            0x0000480a => Some(VmcsField::GuestGsLimit),
            0x0000480c => Some(VmcsField::GuestLdtrLimit),
            0x0000480e => Some(VmcsField::GuestTrLimit),
            0x00004810 => Some(VmcsField::GuestGdtrLimit),
            0x00004812 => Some(VmcsField::GuestIdtrLimit),
            0x00004814 => Some(VmcsField::GuestEsArBytes),
            0x00004816 => Some(VmcsField::GuestCsArBytes),
            0x00004818 => Some(VmcsField::GuestSsArBytes),
            0x0000481a => Some(VmcsField::GuestDsArBytes),
            0x0000481c => Some(VmcsField::GuestFsArBytes),
            0x0000481e => Some(VmcsField::GuestGsArBytes),
            0x00004820 => Some(VmcsField::GuestLdtrArBytes),
            0x00004822 => Some(VmcsField::GuestTrArBytes),
            0x00004824 => Some(VmcsField::GuestInterruptibilityInfo),
            0x00004826 => Some(VmcsField::GuestActivityState),
            0x0000482A => Some(VmcsField::GuestSysenterCs),
            0x0000482E => Some(VmcsField::VmxPreemptionTimerValue),
            0x00004c00 => Some(VmcsField::HostIa32SysenterCs),
            0x00006000 => Some(VmcsField::Cr0GuestHostMask),
            0x00006002 => Some(VmcsField::Cr4GuestHostMask),
            0x00006004 => Some(VmcsField::Cr0ReadShadow),
            0x00006006 => Some(VmcsField::Cr4ReadShadow),
            0x00006008 => Some(VmcsField::Cr3TargetValue0),
            0x0000600a => Some(VmcsField::Cr3TargetValue1),
            0x0000600c => Some(VmcsField::Cr3TargetValue2),
            0x0000600e => Some(VmcsField::Cr3TargetValue3),
            0x00006400 => Some(VmcsField::ExitQualification),
            0x0000640a => Some(VmcsField::GuestLinearAddress),
            0x00006800 => Some(VmcsField::GuestCr0),
            0x00006802 => Some(VmcsField::GuestCr3),
            0x00006804 => Some(VmcsField::GuestCr4),
            0x00006806 => Some(VmcsField::GuestEsBase),
            0x00006808 => Some(VmcsField::GuestCsBase),
            0x0000680a => Some(VmcsField::GuestSsBase),
            0x0000680c => Some(VmcsField::GuestDsBase),
            0x0000680e => Some(VmcsField::GuestFsBase),
            0x00006810 => Some(VmcsField::GuestGsBase),
            0x00006812 => Some(VmcsField::GuestLdtrBase),
            0x00006814 => Some(VmcsField::GuestTrBase),
            0x00006816 => Some(VmcsField::GuestGdtrBase),
            0x00006818 => Some(VmcsField::GuestIdtrBase),
            0x0000681a => Some(VmcsField::GuestDr7),
            0x0000681c => Some(VmcsField::GuestRsp),
            0x0000681e => Some(VmcsField::GuestRip),
            0x00006820 => Some(VmcsField::GuestRflags),
            0x00006822 => Some(VmcsField::GuestPendingDbgExceptions),
            0x00006824 => Some(VmcsField::GuestSysenterEsp),
            0x00006826 => Some(VmcsField::GuestSysenterEip),
            0x00006c00 => Some(VmcsField::HostCr0),
            0x00006c02 => Some(VmcsField::HostCr3),
            0x00006c04 => Some(VmcsField::HostCr4),
            0x00006c06 => Some(VmcsField::HostFsBase),
            0x00006c08 => Some(VmcsField::HostGsBase),
            0x00006c0a => Some(VmcsField::HostTrBase),
            0x00006c0c => Some(VmcsField::HostGdtrBase),
            0x00006c0e => Some(VmcsField::HostIdtrBase),
            0x00006c10 => Some(VmcsField::HostIa32SysenterEsp),
            0x00006c12 => Some(VmcsField::HostIa32SysenterEip),
            0x00006c14 => Some(VmcsField::HostRsp),
            0x00006c16 => Some(VmcsField::HostRip),
            /*Invalid Vmcs values representing general purpose registers.*/
            0xff007000 => Some(VmcsField::GuestRax),
            0xff007002 => Some(VmcsField::GuestRbx),
            0xff007004 => Some(VmcsField::GuestRcx),
            0xff007006 => Some(VmcsField::GuestRdx),
            0xff007008 => Some(VmcsField::GuestRbp),
            0xff00700a => Some(VmcsField::GuestRsi),
            0xff00700c => Some(VmcsField::GuestRdi),
            0xff00700e => Some(VmcsField::GuestR8),
            0xff007010 => Some(VmcsField::GuestR9),
            0xff007012 => Some(VmcsField::GuestR10),
            0xff007014 => Some(VmcsField::GuestR11),
            0xff007016 => Some(VmcsField::GuestR12),
            0xff007018 => Some(VmcsField::GuestR13),
            0xff00701a => Some(VmcsField::GuestR14),
            0xff00701c => Some(VmcsField::GuestR15),
            0xff00701e => Some(VmcsField::GuestLstar),
            _ => None,
        }
    }

    #[inline]
    pub fn raw(&self) -> u32 {
        *self as u32
    }

    /// Get the VmcsField width.
    pub fn width(&self) -> VmcsFieldWidth {
        let raw = self.raw();
        VmcsFieldWidth::from_raw(((raw & VMCS_FIELD_WIDTH_MASK) >> VMCS_FIELD_WIDTH_SHIFT) as u8)
    }

    /// Get the VmcsField type.
    ///
    /// @warning: We're abusing the reserved bit.
    pub fn tpe(&self) -> VmcsFieldType {
        let raw = self.raw();
        VmcsFieldType::from_raw(
            ((raw & (VMCS_FIELD_TYPE_MASK | VMCS_FIELD_RESERVED_LOW_MASK)) >> VMCS_FIELD_TYPE_SHIFT)
                as u8,
        )
    }

    pub fn access_type(&self) -> VmcsFieldAccessType {
        let raw = self.raw();
        VmcsFieldAccessType::from_raw(
            ((raw & VMCS_FIELD_ACCESS_TYPE_MASK) >> VMCS_FIELD_ACCESS_TYPE_SHIFT) as u8,
        )
    }

    pub fn is_guest_cr(&self) -> bool {
        match self {
            VmcsField::GuestCr0 => true,
            VmcsField::GuestCr3 => true,
            VmcsField::GuestCr4 => true,
            _ => false,
        }
    }

    pub fn is_gp_register(&self) -> bool {
        self.tpe() == VmcsFieldType::GuestGP
    }

    /// Rip, Rsp, Cr3.
    pub fn is_context_register(&self) -> bool {
        match *self {
            Self::GuestRsp | Self::GuestRip | Self::GuestCr3 => true,
            _ => false,
        }
    }

    /// Returns true if the field is for sure not supported by the current hardware.
    /// Note that the field might still be unsupported if false is returned.
    ///
    /// TODO: Can we in fact precisely predict which field is supported? I'm not sure with the
    /// manual's wording.
    pub fn is_unsupported(&self) -> bool {
        // SAFETY: This MSR is always supported
        let vmcs_enum = unsafe { VMX_VMCS_ENUM.read() };
        // the bits 9:1 of the MSR must be greater than bits 9:1 of the field encoding.
        // See Intel manual volume 3 annex A.9.
        (self.raw() as u64 & 0b1111111110) > vmcs_enum
    }

    /// Write a VmcsField.
    /// See table 25-21 in chapter 25.11.2 of Intel Manual for encoding.
    pub unsafe fn vmwrite(&self, value: usize) -> Result<(), VmxError> {
        // Check we can write that field.
        if !self.tpe().is_vmwritable() {
            panic!(
                "Figure out what value we should return {:?} {:?}",
                self,
                self.tpe()
            );
        }
        // We convert the values to the right length to avoid setting invalid bits.
        match self.width() {
            VmcsFieldWidth::Width16 => {
                let v: u16 = value as u16;
                raw::vmwrite(self.raw() as u64, v as u64)
            }
            VmcsFieldWidth::Width32 => {
                // Special case for fields with high:low entries.
                if let Some(high) = VmcsField::from_u32(self.raw() + 1) {
                    if self.access_type() == VmcsFieldAccessType::Full
                        && high.access_type() == VmcsFieldAccessType::High
                    {
                        return raw::vmwrite(self.raw() as u64, value as u64);
                    }
                }
                let v: u32 = value as u32;
                raw::vmwrite(self.raw() as u64, v as u64)
            }
            VmcsFieldWidth::Width64 => {
                let v: u64 = value as u64;
                raw::vmwrite(self.raw() as u64, v)
            }
            VmcsFieldWidth::WidthNat => {
                // usize is already natural width?
                raw::vmwrite(self.raw() as u64, value as u64)
            }
        }
    }

    /// Read a VmcsField.
    pub unsafe fn vmread(&self) -> Result<usize, VmxError> {
        if self.is_gp_register() {
            panic!("There should not be a vmread on a general purpose register.");
        }
        raw::vmread(self.raw() as u64).map(|value| value as usize)
    }
}

/// The register file zize
pub const REGFILE_SIZE: usize = 16;
/// Represents general purpose fields not stored in a Vmcs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum GeneralPurposeField {
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

impl GeneralPurposeField {
    pub fn from_raw(v: u32) -> GeneralPurposeField {
        match v {
            0 => GeneralPurposeField::Rax,
            1 => GeneralPurposeField::Rbx,
            2 => GeneralPurposeField::Rcx,
            3 => GeneralPurposeField::Rdx,
            4 => GeneralPurposeField::Rbp,
            5 => GeneralPurposeField::Rsi,
            6 => GeneralPurposeField::Rdi,
            7 => GeneralPurposeField::R8,
            8 => GeneralPurposeField::R9,
            9 => GeneralPurposeField::R10,
            10 => GeneralPurposeField::R11,
            11 => GeneralPurposeField::R12,
            12 => GeneralPurposeField::R13,
            13 => GeneralPurposeField::R14,
            14 => GeneralPurposeField::R15,
            15 => GeneralPurposeField::Lstar,
            _ => panic!("Invalid General Purpose Field."),
        }
    }

    pub fn from_field(v: VmcsField) -> GeneralPurposeField {
        match v {
            VmcsField::GuestRax => GeneralPurposeField::Rax,
            VmcsField::GuestRbx => GeneralPurposeField::Rbx,
            VmcsField::GuestRcx => GeneralPurposeField::Rcx,
            VmcsField::GuestRdx => GeneralPurposeField::Rdx,
            VmcsField::GuestRbp => GeneralPurposeField::Rbp,
            VmcsField::GuestRsi => GeneralPurposeField::Rsi,
            VmcsField::GuestRdi => GeneralPurposeField::Rdi,
            VmcsField::GuestR8 => GeneralPurposeField::R8,
            VmcsField::GuestR9 => GeneralPurposeField::R9,
            VmcsField::GuestR10 => GeneralPurposeField::R10,
            VmcsField::GuestR11 => GeneralPurposeField::R11,
            VmcsField::GuestR12 => GeneralPurposeField::R12,
            VmcsField::GuestR13 => GeneralPurposeField::R13,
            VmcsField::GuestR14 => GeneralPurposeField::R14,
            VmcsField::GuestR15 => GeneralPurposeField::R15,
            VmcsField::GuestLstar => GeneralPurposeField::Lstar,
            _ => panic!("Invalid VmcsField for General Purpose Field."),
        }
    }

    pub fn to_field(&self) -> VmcsField {
        match *self {
            GeneralPurposeField::Rax => VmcsField::GuestRax,
            GeneralPurposeField::Rbx => VmcsField::GuestRbx,
            GeneralPurposeField::Rcx => VmcsField::GuestRcx,
            GeneralPurposeField::Rdx => VmcsField::GuestRdx,
            GeneralPurposeField::Rbp => VmcsField::GuestRbp,
            GeneralPurposeField::Rsi => VmcsField::GuestRsi,
            GeneralPurposeField::Rdi => VmcsField::GuestRdi,
            GeneralPurposeField::R8 => VmcsField::GuestR8,
            GeneralPurposeField::R9 => VmcsField::GuestR9,
            GeneralPurposeField::R10 => VmcsField::GuestR10,
            GeneralPurposeField::R11 => VmcsField::GuestR11,
            GeneralPurposeField::R12 => VmcsField::GuestR12,
            GeneralPurposeField::R13 => VmcsField::GuestR13,
            GeneralPurposeField::R14 => VmcsField::GuestR14,
            GeneralPurposeField::R15 => VmcsField::GuestR15,
            GeneralPurposeField::Lstar => VmcsField::GuestLstar,
        }
    }
}

// ————————————————————————————————— Tests —————————————————————————————————— //

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn fake_field_type() {
        assert_eq!(VmcsField::GuestRax.tpe(), VmcsFieldType::GuestGP);
        assert_eq!(VmcsField::GuestRbx.tpe(), VmcsFieldType::GuestGP);
        assert_eq!(VmcsField::GuestRcx.tpe(), VmcsFieldType::GuestGP);
        assert_eq!(VmcsField::GuestRdx.tpe(), VmcsFieldType::GuestGP);
        assert_eq!(VmcsField::GuestRbp.tpe(), VmcsFieldType::GuestGP);
        assert_eq!(VmcsField::GuestRsi.tpe(), VmcsFieldType::GuestGP);
        assert_eq!(VmcsField::GuestRdi.tpe(), VmcsFieldType::GuestGP);
        assert_eq!(VmcsField::GuestR8.tpe(), VmcsFieldType::GuestGP);
        assert_eq!(VmcsField::GuestR9.tpe(), VmcsFieldType::GuestGP);
        assert_eq!(VmcsField::GuestR10.tpe(), VmcsFieldType::GuestGP);
        assert_eq!(VmcsField::GuestR11.tpe(), VmcsFieldType::GuestGP);
        assert_eq!(VmcsField::GuestR12.tpe(), VmcsFieldType::GuestGP);
        assert_eq!(VmcsField::GuestR13.tpe(), VmcsFieldType::GuestGP);
        assert_eq!(VmcsField::GuestR14.tpe(), VmcsFieldType::GuestGP);
        assert_eq!(VmcsField::GuestR15.tpe(), VmcsFieldType::GuestGP);
        assert_eq!(VmcsField::GuestLstar.tpe(), VmcsFieldType::GuestGP);
    }

    #[test]
    fn fake_field_width() {
        assert_eq!(VmcsField::GuestRax.width(), VmcsFieldWidth::WidthNat);
        assert_eq!(VmcsField::GuestRbx.width(), VmcsFieldWidth::WidthNat);
        assert_eq!(VmcsField::GuestRcx.width(), VmcsFieldWidth::WidthNat);
        assert_eq!(VmcsField::GuestRdx.width(), VmcsFieldWidth::WidthNat);
        assert_eq!(VmcsField::GuestRbp.width(), VmcsFieldWidth::WidthNat);
        assert_eq!(VmcsField::GuestRsi.width(), VmcsFieldWidth::WidthNat);
        assert_eq!(VmcsField::GuestRdi.width(), VmcsFieldWidth::WidthNat);
        assert_eq!(VmcsField::GuestR8.width(), VmcsFieldWidth::WidthNat);
        assert_eq!(VmcsField::GuestR9.width(), VmcsFieldWidth::WidthNat);
        assert_eq!(VmcsField::GuestR10.width(), VmcsFieldWidth::WidthNat);
        assert_eq!(VmcsField::GuestR11.width(), VmcsFieldWidth::WidthNat);
        assert_eq!(VmcsField::GuestR12.width(), VmcsFieldWidth::WidthNat);
        assert_eq!(VmcsField::GuestR13.width(), VmcsFieldWidth::WidthNat);
        assert_eq!(VmcsField::GuestR14.width(), VmcsFieldWidth::WidthNat);
        assert_eq!(VmcsField::GuestR15.width(), VmcsFieldWidth::WidthNat);
        assert_eq!(VmcsField::GuestLstar.width(), VmcsFieldWidth::WidthNat);
    }
}
