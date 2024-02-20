//! VMX bitmaps.
//!
//! Wrappers for simple and tape safe manipulation of bitmaps used throughout VMX operations.

use bitflags::bitflags;

bitflags! {
    /// Pin-based VM-execution controls.
    ///
    /// A set of bitmask flags useful when setting up [`PINBASED_EXEC_CONTROLS`] VMCS field.
    ///
    /// See Intel SDM, Volume 3C, Section 24.6.1.
    pub struct PinbasedControls: u32 {
        /// External-interrupt exiting.
        const EXTERNAL_INTERRUPT_EXITING = 1 << 0;
        /// NMI exiting.
        const NMI_EXITING                = 1 << 3;
        /// Virtual NMIs.
        const VIRTUAL_NMIS               = 1 << 5;
        /// Activate VMX-preemption timer.
        const VMX_PREEMPTION_TIMER       = 1 << 6;
        /// Process posted interrupts.
        const POSTED_INTERRUPTS          = 1 << 7;
    }

    /// Primary processor-based VM-execution controls.
    ///
    /// A set of bitmask flags useful when setting up [`PRIMARY_PROCBASED_EXEC_CONTROLS`] VMCS field.
    ///
    /// See Intel SDM, Volume 3C, Section 24.6.2, Table 24-6.
    pub struct PrimaryControls: u32 {
        /// Interrupt-window exiting.
        const INTERRUPT_WINDOW_EXITING = 1 << 2;
        /// Use TSC offsetting.
        const USE_TSC_OFFSETTING       = 1 << 3;
        /// HLT exiting.
        const HLT_EXITING              = 1 << 7;
        /// INVLPG exiting.
        const INVLPG_EXITING           = 1 << 9;
        /// MWAIT exiting.
        const MWAIT_EXITING            = 1 << 10;
        /// RDPMC exiting.
        const RDPMC_EXITING            = 1 << 11;
        /// RDTSC exiting.
        const RDTSC_EXITING            = 1 << 12;
        /// CR3-load exiting.
        const CR3_LOAD_EXITING         = 1 << 15;
        /// CR3-store exiting.
        const CR3_STORE_EXITING        = 1 << 16;
        /// CR8-load exiting.
        const CR8_LOAD_EXITING         = 1 << 19;
        /// CR8-store exiting.
        const CR8_STORE_EXITING        = 1 << 20;
        /// Use TPR shadow.
        const USE_TPR_SHADOW           = 1 << 21;
        /// NMI-window exiting.
        const NMI_WINDOW_EXITING       = 1 << 22;
        /// MOV-DR exiting
        const MOV_DR_EXITING           = 1 << 23;
        /// Unconditional I/O exiting.
        const UNCOND_IO_EXITING        = 1 << 24;
        /// Use I/O bitmaps.
        const USE_IO_BITMAPS           = 1 << 25;
        /// Monitor trap flag.
        const MONITOR_TRAP_FLAG        = 1 << 27;
        /// Use MSR bitmaps.
        const USE_MSR_BITMAPS          = 1 << 28;
        /// MONITOR exiting.
        const MONITOR_EXITING          = 1 << 29;
        /// PAUSE exiting.
        const PAUSE_EXITING            = 1 << 30;
        /// Activate secondary controls.
        const SECONDARY_CONTROLS       = 1 << 31;
    }

    /// Secondary processor-based VM-execution controls.
    ///
    /// A set of bitmask flags useful when setting up [`SECONDARY_PROCBASED_EXEC_CONTROLS`] VMCS field.
    ///
    /// See Intel SDM, Volume 3C, Section 24.6.2, Table 24-7.
    pub struct SecondaryControls: u32 {
        /// Virtualize APIC accesses.
        const VIRTUALIZE_APIC = 1 << 0;
        /// Enable EPT.
        const ENABLE_EPT = 1 << 1;
        /// Descriptor-table exiting.
        const DTABLE_EXITING = 1 << 2;
        /// Enable RDTSCP.
        const ENABLE_RDTSCP = 1 << 3;
        /// Virtualize x2APIC mode.
        const VIRTUALIZE_X2APIC = 1 << 4;
        /// Enable VPID.
        const ENABLE_VPID = 1 << 5;
        /// WBINVD exiting.
        const WBINVD_EXITING = 1 << 6;
        /// Unrestricted guest.
        const UNRESTRICTED_GUEST = 1 << 7;
        /// APIC-register virtualization.
        const VIRTUALIZE_APIC_REGISTER = 1 << 8;
        /// Virtual-interrupt delivery.
        const VIRTUAL_INTERRUPT_DELIVERY = 1 << 9;
        /// PAUSE-loop exiting.
        const PAUSE_LOOP_EXITING = 1 << 10;
        /// RDRAND exiting.
        const RDRAND_EXITING = 1 << 11;
        /// Enable INVPCID.
        const ENABLE_INVPCID = 1 << 12;
        /// Enable VM functions.
        const ENABLE_VM_FUNCTIONS = 1 << 13;
        /// VMCS shadowing.
        const VMCS_SHADOWING = 1 << 14;
        /// Enable ENCLS exiting.
        const ENCLS_EXITING = 1 << 15;
        /// RDSEED exiting.
        const RDSEED_EXITING = 1 << 16;
        /// Enable PML.
        const ENABLE_PML = 1 << 17;
        /// EPT-violation #VE.
        const EPT_VIOLATION_VE = 1 << 18;
        /// Conceal VMX from PT.
        const CONCEAL_VMX_FROM_PT = 1 << 19;
        /// Enable XSAVES/XRSTORS.
        const ENABLE_XSAVES_XRSTORS = 1 << 20;
        /// Mode-based execute control for EPT.
        const MODE_BASED_EPT = 1 << 22;
        /// Sub-page write permissions for EPT.
        const SUB_PAGE_EPT = 1 << 23;
        /// Intel PT uses guest physical addresses.
        const INTEL_PT_GUEST_PHYSICAL = 1 << 24;
        /// Use TSC scaling.
        const USE_TSC_SCALING = 1 << 25;
        /// Enable user wait and pause.
        const ENABLE_USER_WAIT_PAUSE = 1 << 26;
        /// Enable ENCLV exiting.
        const ENCLV_EXITING = 1 << 28;
    }

    /// VM-exit controls.
    ///
    /// A set of bitmask flags useful when setting up [`VMEXIT_CONTROLS`] VMCS field.
    ///
    /// See Intel SDM, Volume 3C, Section 24.7.
    pub struct ExitControls: u32 {
        /// Save debug controls.
        const SAVE_DEBUG_CONTROLS        = 1 << 2;
        /// Host address-space size.
        const HOST_ADDRESS_SPACE_SIZE    = 1 << 9;
        /// Load IA32_PERF_GLOBAL_CTRL.
        const LOAD_IA32_PERF_GLOBAL_CTRL = 1 << 12;
        /// Acknowledge interrupt on exit.
        const ACK_INTERRUPT_ON_EXIT      = 1 << 15;
        /// Save IA32_PAT.
        const SAVE_IA32_PAT              = 1 << 18;
        /// Load IA32_PAT.
        const LOAD_IA32_PAT              = 1 << 19;
        /// Save IA32_EFER.
        const SAVE_IA32_EFER             = 1 << 20;
        /// Load IA32_EFER.
        const LOAD_IA32_EFER             = 1 << 21;
        /// Save VMX-preemption timer.
        const SAVE_VMX_PREEMPTION_TIMER  = 1 << 22;
        /// Clear IA32_BNDCFGS.
        const CLEAR_IA32_BNDCFGS         = 1 << 23;
        /// Conceal VMX from PT.
        const CONCEAL_VMX_FROM_PT        = 1 << 24;
        /// Clear IA32_RTIT_CTL.
        const CLEAR_IA32_RTIT_CTL        = 1 << 25;
    }

    /// VM-entry controls.
    ///
    /// A set of bitmask flags useful when setting up [`VMENTRY_CONTROLS`] VMCS field.
    ///
    /// See Intel SDM, Volume 3C, Section 24.8.
    pub struct EntryControls: u32 {
        /// Load debug controls.
        const LOAD_DEBUG_CONTROLS        = 1 << 2;
        /// IA-32e mode guest.
        const IA32E_MODE_GUEST           = 1 << 9;
        /// Entry to SMM.
        const ENTRY_TO_SMM               = 1 << 10;
        /// Deactivate dual-monitor treatment.
        const DEACTIVATE_DUAL_MONITOR    = 1 << 11;
        /// Load IA32_PERF_GLOBAL_CTRL.
        const LOAD_IA32_PERF_GLOBAL_CTRL = 1 << 13;
        /// Load IA32_PAT.
        const LOAD_IA32_PAT              = 1 << 14;
        /// Load IA32_EFER.
        const LOAD_IA32_EFER             = 1 << 15;
        /// Load IA32_BNDCFGS.
        const LOAD_IA32_BNDCFGS          = 1 << 16;
        /// Conceal VMX from PT.
        const CONCEAL_VMX_FROM_PT        = 1 << 17;
        /// Load IA32_RTIT_CTL.
        const LOAD_IA32_RTIT_CTL         = 1 << 18;
    }

    // VM-entry interruption-information field (32 bits).
    //
    // A set of bitmask flags useful when setting up the VmEntryIntInfoField VMCS field.
    // This bitmap is incomplete as most bits are used to hold actual values
    // rather than as flags.
    // These two values are used in vmx/errors.rs to create an injectable fault.
    //
    // See Intel SDM, Volume 3C, Section 24.8.3.
    pub struct EntryInterruptionInformationField: u32 {
        /// Deliver error code (0 = do not deliver, 1 = deliver)
        const DELIVER   = 1 << 11;
        /// NMI unblocking due to iret
        const NMI_UNBLOCKING = 1 << 12;
        /// Valid
        const VALID     = 1 << 31;
    }

    /// The exception bitmap.
    ///
    /// Setting a bit to 1 will cause the corresponding exception to trigger a VMExit instead of
    /// being delivered to the guests.
    ///
    /// NOTE: Some exceptions might have higher priority than VMExits, see Intel manual for
    /// details.
    pub struct ExceptionBitmap: u32 {
        /// Dive Error #DE
        const DIVIDE_ERROR             = 1 << 0;
        /// Debug #DB
        const DEBUG                    = 1 << 1;
        /// Non Maskable Interrupt (NMI)
        const NMI                      = 1 << 2;
        /// Breakpoint #BP
        const BREAKPOINT               = 1 << 3;
        /// Overflow #OF
        const OVERFLOW                 = 1 << 4;
        /// Bound range exceeded #BR
        const BOUND_RANGE_EXCEEDED     = 1 << 5;
        /// Invalid Opcode #UD
        const INVALID_OPCODE           = 1 << 6;
        /// Device not available #NM
        const DEVICE_NOT_AVAILABLE     = 1 << 7;
        /// Double fault
        const DOUBLE_FAULT             = 1 << 8;
        /// Invalid TSS exception #TS
        const INVALID_TSS              = 1 << 10;
        /// Segment not present #NP
        const SEGMENT_NOT_PRESENT      = 1 << 11;
        /// Stack segment #SS
        const STACK_SEGMENT_FAULT      = 1 << 12;
        /// General protection fault #GP
        const GENERAL_PROTECTION_FAULT = 1 << 13;
        /// Page fault #PF
        const PAGE_FAULT               = 1 << 14;
        /// x87 floating point #MF
        const X87_FLOATING_POINT       = 1 << 16;
        /// Alignment check #AC
        const ALIGNMENT_CHECK          = 1 << 17;
        /// Machine check #MC
        const MACHINE_CHECK            = 1 << 18;
        /// SIMD floating point #XF
        const SIMD_FLOATING_POINT      = 1 << 19;
        /// ?
        const VIRTUALIZATION           = 1 << 20;
        /// VMM communication #VC
        const VMM_COMMUNICATION        = 1 << 29;
        /// Security #SX
        const SECURITY_EXCEPTION       = 1 << 30;
    }

    /// EPT and VPID capabilities.
    ///
    /// See Intel manual volume 3 annex A.10 for details.
    pub struct EptCapability: u64 {
        // Support execute-only entries.
        const EXECUTE_ONLY             = 1 << 0;
        /// Support page walk of lenght 4.
        const PAGE_WALK_4              = 1 << 6;
        /// Support uncacheable entries.
        const UNCACHEABLE              = 1 << 8;
        /// Support write-back entries.
        const WRITE_BACK               = 1 << 14;
        /// Support 2Mb pages.
        const PAGE_2MB                 = 1 << 16;
        /// Support 1Gb pages.
        const PAGE_1GB                 = 1 << 17;
        /// Support INVEPT instruction.
        const INVEPT                   = 1 << 20;
        /// Support accessed and dirty flags for EPT.
        const ACCESS_DIRTY             = 1 << 21;
        /// Support advanced VM exit information on EPT violation.
        const ADVANCED_VMEXIT          = 1 << 22;
        /// Support single-context INVEPT.
        const SINGLE_CTX_INVEPT        = 1 << 25;
        /// Support all-context INVEPT.
        const ALL_CTX_INVEPT           = 1 << 26;
        /// Support INVVPID.
        const INVVPID                  = 1 << 32;
        /// Support individual-address INVVPID.
        const INDIVIDUAL_ADDR_INVVPID  = 1 << 40;
        /// Support single-context INVVPID.
        const SINGLE_CTX_INVVPID       = 1 << 41;
        /// Support all-context INVVPID.
        const ALL_CTX_INVVPID          = 1 << 42;
        /// Support single-context-retaining-global INVVPID.
        const RETAINING_GLOBAL_INVVPID = 1 << 43;
    }

    /// VM Functions control.
    ///
    /// See Intel manual volume 3 section 24.6.14.
    pub struct VmFuncControls: u64 {
        /// EPTP siwtching.
        const EPTP_SWITCHING = 1 << 0;
    }

    pub struct EptEntryFlags: u64 {
        /// Enable read accesses.
        const READ = 1 << 0;
        /// Enable write accesses.
        const WRITE = 1 << 1;
        /// Enable supervisor-mode execution. If mode-based execute control bit is 0, also control
        /// user-mode execution.
        const SUPERVISOR_EXECUTE = 1 << 2;
        /// ???
        const IGNORE_PAT = 1 << 6;
        /// If 1, points to a data page instead of a page table.
        const PAGE = 1 << 7;
        /// If bit 6 of EPTP is 1, accessed bit flag.
        const ACCESSED = 1 << 8;
        /// If bit 6 of EPTP is 1, dirty bit flag.
        const DIRTY = 1 << 9;
        /// Enable user-mode execution.
        const USER_EXECUTE = 1 << 10;
        /// Suppress EPT-violation faults (#VE).
        const SUPPRESS_VE = 1 << 63;
    }

    pub struct EptMemoryType: u64 {
        const UC = (0 << 3);
        const WC = (1 << 3);
        const WT = (4 << 3);
        const WP = (5 << 3);
        const WB = (6 << 3);
    }

    /// The RFLAGS register.
    pub struct RFlags: u64 {
        /// Processor feature identification flag.
        ///
        /// If this flag is modifiable, the CPU supports CPUID.
        const ID = 1 << 21;
        /// Indicates that an external, maskable interrupt is pending.
        ///
        /// Used when virtual-8086 mode extensions (CR4.VME) or protected-mode virtual
        /// interrupts (CR4.PVI) are activated.
        const VIRTUAL_INTERRUPT_PENDING = 1 << 20;
        /// Virtual image of the INTERRUPT_FLAG bit.
        ///
        /// Used when virtual-8086 mode extensions (CR4.VME) or protected-mode virtual
        /// interrupts (CR4.PVI) are activated.
        const VIRTUAL_INTERRUPT = 1 << 19;
        /// Enable automatic alignment checking if CR0.AM is set. Only works if CPL is 3.
        const ALIGNMENT_CHECK = 1 << 18;
        /// Enable the virtual-8086 mode.
        const VIRTUAL_8086_MODE = 1 << 17;
        /// Allows to restart an instruction following an instrucion breakpoint.
        const RESUME_FLAG = 1 << 16;
        /// Used by `iret` in hardware task switch mode to determine if current task is nested.
        const NESTED_TASK = 1 << 14;
        /// The high bit of the I/O Privilege Level field.
        ///
        /// Specifies the privilege level required for executing I/O address-space instructions.
        const IOPL_HIGH = 1 << 13;
        /// The low bit of the I/O Privilege Level field.
        ///
        /// Specifies the privilege level required for executing I/O address-space instructions.
        const IOPL_LOW = 1 << 12;
        /// Set by hardware to indicate that the sign bit of the result of the last signed integer
        /// operation differs from the source operands.
        const OVERFLOW_FLAG = 1 << 11;
        /// Determines the order in which strings are processed.
        const DIRECTION_FLAG = 1 << 10;
        /// Enable interrupts.
        const INTERRUPT_FLAG = 1 << 9;
        /// Enable single-step mode for debugging.
        const TRAP_FLAG = 1 << 8;
        /// Set by hardware if last arithmetic operation resulted in a negative value.
        const SIGN_FLAG = 1 << 7;
        /// Set by hardware if last arithmetic operation resulted in a zero value.
        const ZERO_FLAG = 1 << 6;
        /// Set by hardware if last arithmetic operation generated a carry ouf of bit 3 of the
        /// result.
        const AUXILIARY_CARRY_FLAG = 1 << 4;
        /// Set by hardware if last result has an even number of 1 bits (only for some operations).
        const PARITY_FLAG = 1 << 2;
        /// Set by hardware if last arithmetic operation generated a carry out of the
        /// most-significant bit of the result.
        const CARRY_FLAG = 1;
    }
}

// —————————————————————————— Exit Qualifications ——————————————————————————— //

pub mod exit_qualification {
    use super::*;
    use crate::fields::VmcsField;

    bitflags! {
        pub struct EptViolation: usize {
            /// Violation due to a read operation.
            const READ = 1 << 0;
            /// Violation due to a write operation.
            const WRITE = 1 << 1;
            /// Violation due to an instruction fetch.
            const EXECUTE = 1 << 2;
            /// indicates wether the guest linear address was readable.
            const GUEST_PHYS_READ = 1 << 3;
            /// Indicate wether the guest linear address was writeable.
            const GUEST_PHYS_WRITE = 1 << 4;
            /// Indicate wether the guest linear address was executable.
            const GUEST_PHYS_EXECUTE = 1 << 5;
            /// If mode based execution control is set, indicate whether the guest user mode linear
            /// address was executable.
            const MODE_BASED_GUEST_PHYS_EXECUTE = 1 << 6;
            /// the guest linear address field from the VMCS is valid.
            const GUEST_LINEAR_IS_VALID = 1 << 7;
            /// If guest linear is valid and set, indicate that the violation results from access
            /// to the guest physical page obtained by translating the linear address. If the guest
            /// linear is valid and this bit is not set, the violation is due to EPT page walk or
            /// update of an access or dirty bit.
            const CAUSED_BY_TRANSLATED_LINEAR_ADDR = 1 << 8;
            /// If guest linear is valid and caused by access to the translated linear address,
            /// indicate whether the address is supervisor-mode or user-mode.
            const GUEST_SUPERVISOR = 1 << 9;
            /// If guest linear is valid and caused by access to the translated linear address,
            /// indicate whether the page is read/write within the guest.
            const GUEST_READ_WRITE = 1 << 10;
            /// If guest linear is valid and caused by access to the translated linear address,
            /// indicate whether the execute access is disabled within the guest.
            const GUEST_EXECUTE_DISABLED = 1 << 11;
            /// NMI blocked due to IRET.
            const NMI_BLOCKED = 1 << 12;
        }
    }

    /// Control Register Accesses qualification.
    ///
    /// See table 27.3.
    #[derive(Clone, Copy, Debug)]
    pub enum ControlRegisterAccesses {
        MovToCr(VmcsField, VmcsField),
        MovFromCr(VmcsField, VmcsField),
        Clts(u16),
        LmswRegister(u16),
        LmswMemory(u16),
    }
}
