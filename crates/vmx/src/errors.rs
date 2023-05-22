//! VMX Errors

use super::bitmaps::EntryInterruptionInformationField;

/// An error that occured during VMX operations.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum VmxError {
    /// VMCS pointer is valid, but some other error was encountered. Read VM-instruction error
    /// field of VMCS for more details.
    VmFailValid(VmxInstructionError),

    /// VMCS pointer is invalid.
    VmFailInvalid,

    /// VMX is not supported by the current CPU.
    VmxNotSupported,

    /// VMX is supported by the CPU but not enabled. See IA_32_FEATURE_CONTROL MSR.
    VmxNotEnabled,

    /// A particular feature is not supported.
    FeatureNotSupported,

    /// Value 1 is not supported for one of the configuration bits for which it was requested.
    Disallowed1(VmxFieldError, u8),

    /// Value 0 is not supported for one of the configuration bits for which it was requested.
    Disallowed0(VmxFieldError, u8),

    /// Current value of the bit is not valid. This can be caused by an equality requirement
    /// between two fields for instance.
    MisconfiguredBit(VmxFieldError, u8),

    /// Current value of the field is not valid. This might be due to restrictions on multiple
    /// bits, for instance a range of the bits might have fixed possible values.
    Misconfigured(VmxFieldError),
}

impl VmxError {
    /// If the error is either a disallowed 0 or a disallowed 1, override the faulty VMX field.
    pub(crate) fn set_field(self, field: VmxFieldError) -> Self {
        match self {
            Self::Disallowed0(_, idx) => Self::Disallowed0(field, idx),
            Self::Disallowed1(_, idx) => Self::Disallowed1(field, idx),
            Self::MisconfiguredBit(_, idx) => Self::MisconfiguredBit(field, idx),
            _ => self,
        }
    }
}

/// An error resulting from the execution of a VMX instruction.
///
/// See Intel Manual 3C Section 30.4.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum VmxInstructionError {
    /// VMCA executed in VMX-root operation.
    VmCallRoot,
    /// VMCLEAR with invalid physical address.
    VmClearInvalid,
    /// VMCLEAR with VMXON pointer.
    VmClearVmxon,
    /// VMLAUNCH with non-clear VMCS.
    VmLaunchNonClear,
    /// VMRESUME with non-launched VMCS.
    VmResumeNonLaunched,
    /// VMRESUME after VMXOFF.
    VmResumeAfterVmxoff,
    /// VMENTRY with invalid control fields.
    VmEntryInvalidCtrlFields,
    /// VMENTRY with invalid host state.
    VmEntryInvalidHostState,
    /// VMPTRLD with invalid physical address.
    VmPtrldInvalidPhysAddr,
    /// VMPTRLD with VMXON pointer.
    VmPtrldVmxon,
    /// VMPTRLD with incorrect VMCS revision identifier.
    VmPtrldInvalidRevId,
    /// VMREAD/VMWRITE to unsupported component.
    VmAccessUnsupportedField,
    /// VMWRITE to read-only component.
    VmWriteToReadOnly,
    /// VMXON executed in VMX root operation.
    VmxonDuringVmxRoot,
    /// VM entry with invalid executive-VMCS pointer.
    VmEntryInvalidVmcs,
    /// VM entry with non-launched executive VMCS.
    VmEntryNonLaunched,
    /// VM entry with executive-VMCS pointer not VMXON pointer.
    VmEntryVmcsNotVmxon,
    /// VMCALL with non-clear VMCS.
    VmCallNonClearVmcs,
    /// VMCA with invalid VM-exit control fields,
    VmCallInvalidExitCtrlFields,
    /// VMCALL with incorrect MSEG revision identifier.
    VmCallInvalidRevId,
    /// VMXOFF under dual-monitor treatment of SMIs and SMM.
    VmxoffDualMonitor,
    /// VMCALL with invalid SMM-monitor features.
    VmCallInvalidSmmFeatures,
    /// VM entry with invalid VM-execution control fields in executive VMCS.
    VmEntryInvalidExecCtrlFields,
    /// VM entry with events blocked by MOV SS.
    VmEntryBlockedMovSS,
    /// Invalid operand to INVEPT/INVVPID.
    InvalidInvEptInvPid,
    /// Unknown error.
    Unknown,
}

impl VmxInstructionError {
    pub fn from_u64(err: u64) -> VmxInstructionError {
        match err {
            1 => Self::VmCallRoot,
            2 => Self::VmClearInvalid,
            3 => Self::VmClearVmxon,
            4 => Self::VmLaunchNonClear,
            5 => Self::VmResumeNonLaunched,
            6 => Self::VmResumeAfterVmxoff,
            7 => Self::VmEntryInvalidCtrlFields,
            8 => Self::VmEntryInvalidHostState,
            9 => Self::VmPtrldInvalidPhysAddr,
            10 => Self::VmPtrldVmxon,
            11 => Self::VmPtrldInvalidRevId,
            12 => Self::VmAccessUnsupportedField,
            13 => Self::VmWriteToReadOnly,
            15 => Self::VmxonDuringVmxRoot,
            16 => Self::VmEntryInvalidVmcs,
            17 => Self::VmEntryNonLaunched,
            18 => Self::VmEntryVmcsNotVmxon,
            19 => Self::VmCallNonClearVmcs,
            20 => Self::VmCallInvalidExitCtrlFields,
            22 => Self::VmCallInvalidRevId,
            23 => Self::VmxoffDualMonitor,
            24 => Self::VmCallInvalidSmmFeatures,
            25 => Self::VmEntryInvalidExecCtrlFields,
            26 => Self::VmEntryBlockedMovSS,
            28 => Self::InvalidInvEptInvPid,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum VmxFieldError {
    // Host
    HostCr0,
    HostCr4,
    HostCsSelector,
    HostDsSelector,
    HostEsSelector,
    HostFsSelector,
    HostGsSelector,
    HostSsSelector,
    HostTrSelector,

    // Guest
    GuestCr0,
    GuestCr4,
    GuestTrSelector,
    GuestSsSelector,
    GuestCsAccessRights,
    GuestSsAccessRights,
    GuestDsAccessRights,
    GuestEsAccessRights,
    GuestFsAccessRights,
    GuestGsAccessRights,
    GuestTrAccessRights,
    GuestGdtrLimit,
    GuestIdtrLimit,
    GuestRflags,

    // Controls
    PinBasedControls,
    PrimaryControls,
    SecondaryControls,
    ExitControls,
    EntryControls,
    VmFuncControls,
    VmExitMsrStoreAddr,
    VmExitMsrLoadAddr,
    VmEntryIntInfoField,
    VmEntryMsrLoadAddr,
    MsrBitmaps,

    // Other
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmExitInterrupt {
    /// Vector ID of interrupt or exception.
    pub vector: u8,
    /// Interruption type
    pub int_type: InterruptionType,
    /// Error code, if defined for the interrupt.
    pub error_code: Option<u32>,
}

/// Transforms a VmExitInterrupt into a valid VmEntryIntInfoField for event injection.
///
/// @warn apparently setting the deliver bit results in invalid ctrls fields
/// upon a vmresume.
impl VmExitInterrupt {
    pub fn as_injectable_u32(&self) -> u32 {
        let mut res: u32 = 0;
        res |= self.vector as u32;
        res |= (self.int_type as u32) << 8;
        res |= EntryInterruptionInformationField::DELIVER.bits();
        res |= EntryInterruptionInformationField::VALID.bits();
        return res;
    }
}

/// Interruption type.
///
/// Generated on VM exit due to an interruption with corresponding exception bitmap bit set to 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptionType {
    ExternalInterrupt,
    Reserved,
    NonMaskableInterrupt,
    HardwareException,
    PrivilegedSoftwareException,
    SoftwareException,
    Unknown,
}

impl InterruptionType {
    /// Return the interrupt type from the raw VM-exit interrupt information field.
    pub fn from_raw(info: u32) -> Self {
        let id = (info >> 8) & 0b111;
        match id {
            0 => Self::ExternalInterrupt,
            1 => Self::Reserved,
            2 => Self::NonMaskableInterrupt,
            3 => Self::HardwareException,
            4 => Self::PrivilegedSoftwareException,
            6 => Self::SoftwareException,
            _ => Self::Unknown,
        }
    }
}

/// The basic VM Exit reason.
///
/// See Intel manual volule 3 annex C.
#[rustfmt::skip]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[repr(u16)]
pub enum VmxExitReason {
    /// An exception or non-maskable interrupt (NMI) with the corresponding exception bit is set to
    /// 1 in the exception bitmap, or if "NMI exiting" control is set to 1.
    Exception                       = 0,
    /// An external interrupt with "external-interrupt exiting" control bit is set to 1.
    ExternalInterrupt               = 1,
    /// Triple fault.
    TripleFault                     = 2,
    /// INIT signal.
    InitSignal                      = 3,
    /// Start-up IPI (SIPI) signal while the processor was in "wait for SIPI" state.
    StartUpIpi                      = 4,
    /// An I/O system-management interrupt (SMI) arrived immediately after retirement of an I/O
    /// instruction and caused a SMM VM exit.
    IoSystemManagementInterrupt     = 5,
    /// An SMI  arrived and caused an SMM VM Exit.
    OtherSmi                        = 6,
    /// At the beginning of an instruction, RFLAGS.IF was 1, events were not blocked by STI or by
    /// MOV SS and the "interrupt-window exiting" control bit was set to 1.
    InterruptWindow                 = 7,
    /// At the beginning of an instruction, there was no virtual NMI blocking, events were not
    /// blocked by MOV SS and the "NMI-window exiting" control bit was set to 1.
    NmiWindow                       = 8,
    /// Guest software attempted to task switch.
    TaskSwitch                      = 9,
    /// Guest software attempted to execute CPUID.
    Cpuid                           = 10,
    /// Guest software attempted to execute GETSEC.
    Getsec                          = 11,
    /// Guest software attempted to execute HLT with the "HLT exiting" control bit set to 1.
    Hlt                             = 12,
    /// Guest software attempted to execute INVD.
    Invd                            = 13,
    /// Guest software attempted to execute INVLPG with the "INVPG exiting" control bit set to 1.
    Invlpd                          = 14,
    /// Guest software attempted to execute RDPMC with he "RDPMC exiting" control bit set to 1.
    Rdpmc                           = 15,
    /// Guest software attempted to execute RDTSC with the "RDTSC exiting" control bit set to 1.
    Rdtsc                           = 16,
    /// Guest software attempted to execute RSM in SMM.
    Rsm                             = 17,
    /// VMCALL was executed by guest software.
    Vmcall                          = 18,
    /// Guest software attempted to execute VMCLEAR.
    Vmclear                         = 19,
    /// Guest software attempted to execute VMLAUNCH.
    Vmlaunch                        = 20,
    /// Guest software attempted to execute VMPTRLD.
    Vmptrld                         = 21,
    /// Guest software attempted to execute VMPTRST.
    Vmptrst                         = 22,
    /// Guest software attempted to execute VMREAD.
    Vmread                          = 23,
    /// Guest software attempted to execute VMRESUME.
    Vmresume                        = 24,
    /// Guest software attempted to execute VMWRITE.
    Vmwrite                         = 25,
    /// Guest software attempted to execute VMXOFF.
    Vmxoff                          = 26,
    /// Guest software attempted to execute VMXON.
    Vmxon                           = 27,
    /// Guest software attempted to access CR0, CR3, CR4 or CR8 using CLTS, LMSW or MOV CR and the
    /// VM execution control fields indicate that a VM exit should occur.
    ControlRegisterAccesses         = 28,
    /// Guest software attempted a MOV to or from a debug register and the "MOV DR exiting" control
    /// bit is set to 1.
    MovDR                           = 29,
    /// Guest software attempted to use an I/O instruction.
    ///
    /// Either:
    /// - The "use I/O bitmap" control bit was 0 and the "unconditional I/O exiting" control bit
    /// was 1.
    /// - The "use I/O bitmap" control bit was 1 and the bit in the I/O bitmap associated with one
    /// of the ports accessed by the I/O instruction was 1.
    IoInstruction                   = 30,
    /// Guest software attempted to use the RDSMR instruction.
    ///
    /// Either:
    /// - the "use MSR bitmaps" control bit was 0.
    /// - The value of RCX is invalid.
    /// - The corresponding value in the bitmap is 1.
    Rdmsr                           = 31,
    /// Guest software attempted to use the WRMSR instruction.
    ///
    /// Either:
    /// - the "usr MSR bitmaps" control bit was 0.
    /// - The value of RCS is invalid.
    /// - the corresponding value in the bitmap is 1.
    Wrmsr                           = 32,
    /// A VM entry failed due to invalid guest state.
    VmEntryFailureInvalidGuestState = 33,
    /// A VM entry failed due to a failed attempt to load MSRs.
    VmEntryFailureMsrLoading        = 34,
    /// Guest software attempted to execute MWAIT and the "MWAIT exiting" control bit is 1.
    Mwait                           = 36,
    /// A VM entry occurred due to the 1-setting of the "monitor trap flag" control bit and
    /// injection of a MTF VM exit as part of a VM entry.
    MonitorTrapFlag                 = 37,
    /// Guest software attempted to use MONITOR and the "MONITOR exiting" control bit is 1.
    Monitor                         = 39,
    /// Guest software attempted to execute PAUSE and the "PAUSE exiting" control bit is 1, or the
    /// "PAUSE-loop exiting" control bit is 1 and guest software executed a PAUSE loop with
    /// execution time exceeding PLE_Window.
    Pause                           = 40,
    /// A machine-check event occurred during VM entry.
    VmEntryFailureMachineCheck      = 41,
    /// TODO
    TPRBelowThreshold               = 43,
    /// Guest Software attempted to access memory at a physical address of the APIC-access page and
    /// the "virtualize APIC accesses" control bit is 1.
    ApicAccess                      = 44,
    /// EOI virtualization was performed for a virtual interrupt whose vector indexed a bit set in
    /// the EOI exit bitmap.
    VirtualizedEoi                  = 45,
    /// Guest software attempted to execute LGDT, LIDT, SGDT, SIDT and the "descriptor-table
    /// exiting" control bit is 1.
    AccessToGdtrOrIdtr              = 46,
    /// Guest software attempted to execute LLDT, LTR, SLDT, STR and the "descriptor table exiting"
    /// control bit is 1.
    AccessToLdtrOrTr                = 47,
    /// Attempt to access memory with guest-physical address disallowed by EPT paging structure.
    EptViolation                    = 48,
    /// Attemot to access memory encountered a misconfigured EPT paging-structure entry.
    EptMisconfiguration             = 49,
    /// Guest software attempted to execute INVEPT.
    Invept                          = 50,
    /// Guest software attempted to execute RDTSCP and the "enable RDTSCP" and "RDTSCP exiting"
    /// control bits are both 1.
    RDTSCP                          = 51,
    /// The preemption timer counted down to zero.
    VmxPreemptionTimerExpired       = 52,
    /// Guest software attempted to execute INVVPID.
    Invvpid                         = 53,
    /// Guest software attempted to execute WBINVD and the "WBINVD exiting" control bit is 1.
    Wbinvd                          = 54,
    // Guest software attempted to execute XSETBV.
    Xsetbv                          = 55,
    /// Guest software completed a write to the virtual-APIC page that must be virtualized by the
    /// VMM.
    ApicWrite                       = 56,
    /// Guest software attempted to execute RDRAND and the "RDRAND exiting" control bit is 1.
    Rdrand                          = 57,
    /// Guest software attempted to execute INVPCID and the "enable INVPCID" and "INVPCID exiting"
    /// control bits are both 1.
    Invpcid                         = 58,
    /// Guest software invoked a VM function with the VMFUNC instruction and the VM function either
    /// was not enabled or generated a function-specific condition that genrated a VM exit.
    Vmfunc                          = 59,
    ///  Guest software attempted to execute ENCLS and “enable ENCLS exiting” control
    ///  bit is 1 and either:
    ///  - EAX < 63 and the corresponding bit in the ENCLS-exiting bitmap is 1.
    ///  - EAX ≥ 63 and bit 63 in the ENCLS-exiting bitmap is 1.
    Encls                           = 60,
    /// Guest software attempted to execute RDSEED and the "RDSEED exiting" control bit is 1.
    Rdseed                          = 61,
    /// The processor attempted to create a page-modification log entry and the value of the
    /// PML index was not in the range 0–511
    PageModificationLogFull         = 62,
    /// Guest software attempted to execute XSAVES and the "enable XSAVES/XRESTORS" control bit is
    /// set to 1, and IA32_XSS and XSS bitmap are configured for exit.
    Xsaves                          = 63,
    /// Guest software attempted to execute XRSTORS and the "enable XSAVES/XRESTORS" control bit is
    /// set to 1, and IA32_XSS and XSS bitmap are configured for exit.
    Xrstors                         = 64,
    /// An unknown exit reason.
    Unknown,
}

impl VmxExitReason {
    pub fn from_u16(reason: u16) -> Self {
        match reason {
            0 => VmxExitReason::Exception,
            1 => VmxExitReason::ExternalInterrupt,
            2 => VmxExitReason::TripleFault,
            3 => VmxExitReason::InitSignal,
            4 => VmxExitReason::StartUpIpi,
            5 => VmxExitReason::IoSystemManagementInterrupt,
            6 => VmxExitReason::OtherSmi,
            7 => VmxExitReason::InterruptWindow,
            8 => VmxExitReason::NmiWindow,
            9 => VmxExitReason::TaskSwitch,
            10 => VmxExitReason::Cpuid,
            11 => VmxExitReason::Getsec,
            12 => VmxExitReason::Hlt,
            13 => VmxExitReason::Invd,
            14 => VmxExitReason::Invlpd,
            15 => VmxExitReason::Rdpmc,
            16 => VmxExitReason::Rdtsc,
            17 => VmxExitReason::Rsm,
            18 => VmxExitReason::Vmcall,
            19 => VmxExitReason::Vmclear,
            20 => VmxExitReason::Vmlaunch,
            21 => VmxExitReason::Vmptrld,
            22 => VmxExitReason::Vmptrst,
            23 => VmxExitReason::Vmread,
            24 => VmxExitReason::Vmresume,
            25 => VmxExitReason::Vmwrite,
            26 => VmxExitReason::Vmxoff,
            27 => VmxExitReason::Vmxon,
            28 => VmxExitReason::ControlRegisterAccesses,
            29 => VmxExitReason::MovDR,
            30 => VmxExitReason::IoInstruction,
            31 => VmxExitReason::Rdmsr,
            32 => VmxExitReason::Wrmsr,
            33 => VmxExitReason::VmEntryFailureInvalidGuestState,
            34 => VmxExitReason::VmEntryFailureMsrLoading,
            36 => VmxExitReason::Mwait,
            37 => VmxExitReason::MonitorTrapFlag,
            39 => VmxExitReason::Monitor,
            40 => VmxExitReason::Pause,
            41 => VmxExitReason::VmEntryFailureMachineCheck,
            43 => VmxExitReason::TPRBelowThreshold,
            44 => VmxExitReason::ApicAccess,
            45 => VmxExitReason::VirtualizedEoi,
            46 => VmxExitReason::AccessToGdtrOrIdtr,
            47 => VmxExitReason::AccessToLdtrOrTr,
            48 => VmxExitReason::EptViolation,
            49 => VmxExitReason::EptMisconfiguration,
            50 => VmxExitReason::Invept,
            51 => VmxExitReason::RDTSCP,
            52 => VmxExitReason::VmxPreemptionTimerExpired,
            53 => VmxExitReason::Invvpid,
            54 => VmxExitReason::Wbinvd,
            55 => VmxExitReason::Xsetbv,
            56 => VmxExitReason::ApicWrite,
            57 => VmxExitReason::Rdrand,
            58 => VmxExitReason::Invpcid,
            59 => VmxExitReason::Vmfunc,
            60 => VmxExitReason::Encls,
            61 => VmxExitReason::Rdseed,
            62 => VmxExitReason::PageModificationLogFull,
            63 => VmxExitReason::Xsaves,
            64 => VmxExitReason::Xrstors,
            _ => VmxExitReason::Unknown,
        }
    }
}

/// Trap numbers for interrupt exit vector values.
#[rustfmt::skip]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[repr(u8)]
pub enum Trapnr {
    /// Divide Error #DE.
    DivideError             = 0,
    /// NMI Interrupt.
    NMI                     = 2,
    /// Breakpoint #BP.
    Breakpoint              = 3,
    /// Overflow #OF.
    Overflow                = 4,
    /// Bound Range Exceeded #BR.
    BoundRangeExceeded      = 5,
    /// Invalid Opcode #UD.
    InvalidOpcode           = 6,
    /// Device Not Available #NM.
    DeviceNotAvailable      = 7,
    /// Double Fault #DF.
    DoubleFault             = 8,
    /// Invalid TSS #TS.
    InvalidTSS              = 10,
    /// Segment Not present #NP.
    SegmentNotPresentFault  = 11,
    /// Stack-Segment #SS.
    StackSegmentFault       = 12,
    /// General Protection #GP.
    GeneralProtectionFault  = 13,
    ///Page fault #PF.
    PageFault               = 14,
    /// x87 FPU fp error #MF.
    FPUError                = 16,
    /// Alignment Check #AC.
    AlignmentCheck          = 17,
    /// Machine Check #MC.
    MachineCheck            = 18,
    /// SIMD fp exception #XM.
    SIMDException           = 19,
    /// Virtualization exception #VE.
    VirtualizationException = 20,
    /// Default is reserved
    Reserved                = 21,
}

impl Trapnr {
    pub fn as_u8(self) -> u8 {
        return self as u8;
    }
}
