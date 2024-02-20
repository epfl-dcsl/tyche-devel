//! VMX operations

use core::arch as platform;
use core::arch::asm;

use stage_two_abi::GuestInfo;
use vmx::bitmaps::{
    EntryControls, ExitControls, PinbasedControls, PrimaryControls, SecondaryControls,
};
use vmx::fields::VmcsField;
use vmx::{secondary_controls_capabilities, ActiveVmcs, VmxError};

use super::arch;
use super::context::Contextx86;
use crate::allocator::{allocator, FrameAllocator};

pub const MSR_IA32_CR_PAT_DEFAULT: usize = 0x0007040600070406;

pub unsafe fn init_vcpu<'vmx>(
    vcpu: &mut ActiveVmcs<'vmx>,
    info: &GuestInfo,
    context: &mut Contextx86,
) {
    let allocator = allocator();
    default_vmcs_config(vcpu, info, false);
    let bit_frame = allocator
        .allocate_frame()
        .expect("Failed to allocate MSR bitmaps")
        .zeroed();
    let msr_bitmaps = vcpu
        .initialize_msr_bitmaps(bit_frame)
        .expect("Failed to install MSR bitmaps");
    msr_bitmaps.allow_all();
    context
        .set(VmcsField::GuestRip, info.rip, Some(vcpu))
        .unwrap();
    context
        .set(VmcsField::GuestCr3, info.cr3, Some(vcpu))
        .unwrap();
    context
        .set(VmcsField::GuestRsp, info.rsp, Some(vcpu))
        .unwrap();
    context
        .set(VmcsField::GuestRsi, info.rsi, Some(vcpu))
        .unwrap();
    // VMXE flags, required during VMX operations.
    let vmxe = 1 << 13;
    let cr4 = 0xA0 | vmxe;
    context.set(VmcsField::GuestCr4, cr4, Some(vcpu)).unwrap();
    context
        .set(VmcsField::Cr4GuestHostMask, vmxe, Some(vcpu))
        .unwrap();
    context
        .set(VmcsField::Cr4ReadShadow, vmxe, Some(vcpu))
        .unwrap();
    vmx::check::check().expect("check error");
}

fn default_vmcs_config(vmcs: &mut ActiveVmcs, info: &GuestInfo, switching: bool) {
    // Look for XSAVES capabilities
    let capabilities =
        secondary_controls_capabilities().expect("Secondary controls are not supported");
    let xsaves = capabilities.contains(SecondaryControls::ENABLE_XSAVES_XRSTORS);

    let err = vmcs
        .set_pin_based_ctrls(PinbasedControls::empty())
        .and_then(|_| {
            vmcs.set_vm_exit_ctrls(
                ExitControls::HOST_ADDRESS_SPACE_SIZE
                    | ExitControls::LOAD_IA32_EFER
                    | ExitControls::SAVE_IA32_EFER
                    | ExitControls::SAVE_IA32_PAT
                    | ExitControls::LOAD_IA32_PAT,
            )
        })
        .and_then(|_| {
            vmcs.set_vm_entry_ctrls(
                EntryControls::IA32E_MODE_GUEST
                    | EntryControls::LOAD_IA32_EFER
                    | EntryControls::LOAD_IA32_PAT,
            )
        })
        .and_then(|_| vmcs.set_exception_bitmap(ExceptionBitmap::empty()))
        .and_then(|_| save_host_state(vmcs, info))
        .and_then(|_| setup_guest(vmcs, info));
    log::info!("Config: {:?}", err);
    log::info!("MSRs:   {:?}", configure_msr());
    log::info!(
        "1'Ctrl: {:?}",
        vmcs.set_primary_ctrls(
            PrimaryControls::SECONDARY_CONTROLS | PrimaryControls::USE_MSR_BITMAPS
        )
    );

    let mut secondary_ctrls = SecondaryControls::ENABLE_RDTSCP
        | SecondaryControls::ENABLE_EPT
        | SecondaryControls::UNRESTRICTED_GUEST;
    if switching {
        secondary_ctrls |= SecondaryControls::ENABLE_VM_FUNCTIONS
    }
    if xsaves {
        secondary_ctrls |= SecondaryControls::ENABLE_XSAVES_XRSTORS;
    }
    secondary_ctrls |= cpuid_secondary_controls();
    log::info!(
        "2'Ctrl {:b}, {:b}",
        secondary_ctrls,
        vmx::secondary_controls_capabilities().expect("meh")
    );
    vmcs.set_secondary_ctrls(secondary_ctrls)
        .expect("Error setting secondary controls");

    // For linux if we want to be able to save/restore pat. No clue why.
    vmcs.set(VmcsField::GuestIa32Pat, MSR_IA32_CR_PAT_DEFAULT)
        .expect("Unable to set PAT");
}

fn configure_msr() -> Result<(), VmxError> {
    unsafe {
        VmcsField::VmExitMsrLoadCount.vmwrite(0)?;
        VmcsField::VmExitMsrStoreCount.vmwrite(0)?;
        VmcsField::VmEntryMsrLoadCount.vmwrite(0)?;
    }

    Ok(())
}

fn setup_guest(vcpu: &mut ActiveVmcs, info: &GuestInfo) -> Result<(), VmxError> {
    // Mostly copied from https://nixhacker.com/developing-hypervisor-from-scratch-part-4/

    // Control registers
    let cr0: usize;
    let cr3: usize;
    let cr4: usize;
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        vcpu.set(VmcsField::GuestCr0, cr0)?;
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        vcpu.set(VmcsField::GuestCr3, cr3)?;
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        vcpu.set(VmcsField::GuestCr4, cr4)?;
    }

    // Segments selectors
    vcpu.set(VmcsField::GuestEsSelector, 0)?;
    vcpu.set(VmcsField::GuestCsSelector, 0)?;
    vcpu.set(VmcsField::GuestSsSelector, 0)?;
    vcpu.set(VmcsField::GuestDsSelector, 0)?;
    vcpu.set(VmcsField::GuestFsSelector, 0)?;
    vcpu.set(VmcsField::GuestGsSelector, 0)?;
    vcpu.set(VmcsField::GuestTrSelector, 0)?;
    vcpu.set(VmcsField::GuestLdtrSelector, 0)?;
    // Segments access rights
    vcpu.set(VmcsField::GuestEsArBytes, 0xC093)?;
    vcpu.set(VmcsField::GuestCsArBytes, 0xA09B)?;
    vcpu.set(VmcsField::GuestSsArBytes, 0x10000)?;
    vcpu.set(VmcsField::GuestDsArBytes, 0xC093)?;
    vcpu.set(VmcsField::GuestFsArBytes, 0x10000)?;
    vcpu.set(VmcsField::GuestGsArBytes, 0x10000)?;
    vcpu.set(VmcsField::GuestTrArBytes, 0x8B)?;
    vcpu.set(VmcsField::GuestLdtrArBytes, 0x10000)?;
    // Segments limits
    vcpu.set(VmcsField::GuestEsLimit, 0xFFFF)?;
    vcpu.set(VmcsField::GuestCsLimit, 0xFFFF)?;
    vcpu.set(VmcsField::GuestSsLimit, 0xFFFF)?;
    vcpu.set(VmcsField::GuestDsLimit, 0xFFFF)?;
    vcpu.set(VmcsField::GuestFsLimit, 0xFFFF)?;
    vcpu.set(VmcsField::GuestGsLimit, 0xFFFF)?;
    vcpu.set(VmcsField::GuestTrLimit, 0xFF)?; // At least 0x67
    vcpu.set(VmcsField::GuestLdtrLimit, 0xFFFF)?;
    vcpu.set(VmcsField::GuestGdtrLimit, 0xFFFF)?;
    vcpu.set(VmcsField::GuestIdtrLimit, 0xFFFF)?;
    // Segments bases
    vcpu.set(VmcsField::GuestEsBase, 0)?;
    vcpu.set(VmcsField::GuestCsBase, 0)?;
    vcpu.set(VmcsField::GuestSsBase, 0)?;
    vcpu.set(VmcsField::GuestDsBase, 0)?;
    vcpu.set(VmcsField::GuestFsBase, 0)?;
    vcpu.set(VmcsField::GuestGsBase, 0)?;
    vcpu.set(VmcsField::GuestTrBase, 0)?;
    vcpu.set(VmcsField::GuestLdtrBase, 0)?;
    vcpu.set(VmcsField::GuestGdtrBase, 0)?;
    vcpu.set(VmcsField::GuestIdtrBase, 0)?;

    // MSRs
    if VmcsField::GuestIa32Efer.is_unsupported() {
        log::warn!("Ia32Efer field is not supported");
    }
    vcpu.set(VmcsField::GuestIa32Efer, info.efer as usize)?;
    vcpu.set(VmcsField::GuestRflags, 0x2)?;

    vcpu.set(VmcsField::GuestActivityState, 0)?;
    vcpu.set(VmcsField::VmcsLinkPointer, usize::max_value())?;
    vcpu.set(VmcsField::GuestIntrStatus, 0)?;
    // vcpu.set16(fields::GuestState16::PmlIndex, 0)?; // <- Not supported on dev server
    vcpu.set(VmcsField::VmxPreemptionTimerValue, 0)?;

    Ok(())
}

/// Returns optional secondary controls depending on the host cpuid.
fn cpuid_secondary_controls() -> SecondaryControls {
    let mut controls = SecondaryControls::empty();
    let capabilities = vmx::secondary_controls_capabilities()
        .expect("Unable to read secondary controls capabilities");
    let cpuid = unsafe { platform::x86_64::__cpuid(7) };
    if (cpuid.ebx & vmx::CPUID_EBX_X64_FEATURE_INVPCID != 0)
        && (capabilities.bits() & SecondaryControls::ENABLE_INVPCID.bits() != 0)
    {
        controls |= SecondaryControls::ENABLE_INVPCID;
    }
    if (cpuid.ecx & vmx::CPUID_ECX_X64_WAITPGK != 0)
        && (capabilities.bits() & SecondaryControls::ENABLE_USER_WAIT_PAUSE.bits() != 0)
    {
        controls |= SecondaryControls::ENABLE_USER_WAIT_PAUSE;
    }
    return controls;
}

/// Saves the host state (control registers, segments...), so that they are restored on VM Exit.
fn save_host_state<'vmx>(_vmcs: &mut ActiveVmcs<'vmx>, info: &GuestInfo) -> Result<(), VmxError> {
    // NOTE: See section 24.5 of volume 3C.

    let tr: u16;
    let gdt = arch::get_gdt_descriptor();
    let idt = arch::get_idt_descriptor();

    unsafe {
        // There is no nice wrapper to read `tr` in the x86_64 crate.
        asm!("str {0:x}",
                out(reg) tr,
                options(att_syntax, nostack, nomem, preserves_flags));
    }

    unsafe {
        VmcsField::HostCsSelector.vmwrite(info.cs as usize)?;
        VmcsField::HostDsSelector.vmwrite(info.ds as usize)?;
        VmcsField::HostEsSelector.vmwrite(info.es as usize)?;
        VmcsField::HostFsSelector.vmwrite(info.fs as usize)?;
        VmcsField::HostGsSelector.vmwrite(info.gs as usize)?;
        VmcsField::HostSsSelector.vmwrite(info.ss as usize)?;
        VmcsField::HostTrSelector.vmwrite(tr as usize)?;

        // NOTE: those might throw an exception depending on the CPU features, let's just
        // ignore them for now.
        // VmcsHostStateNat::FsBase.vmwrite(FS::read_base().as_u64() as usize)?;
        // VmcsHostStateNat::GsBase.vmwrite(GS::read_base().as_u64() as usize)?;

        VmcsField::HostIdtrBase.vmwrite(idt.base as usize)?;
        VmcsField::HostGdtrBase.vmwrite(gdt.base as usize)?;

        // Save TR base
        // let tr_offset = (tr >> 3) as usize;
        // let gdt = gdt::gdt().as_raw_slice();
        // let low = gdt[tr_offset];
        // let high = gdt[tr_offset + 1];
        // let tr_base = get_tr_base(high, low);
        // fields::HostStateNat::TrBase.vmwrite(tr_base as usize)?;
    }

    // MSRs
    unsafe {
        VmcsField::HostIa32Efer.vmwrite(info.efer as usize)?;
        VmcsField::HostIa32Pat.vmwrite(MSR_IA32_CR_PAT_DEFAULT)?;
    }

    // Control registers
    let cr0: usize;
    let cr3: usize;
    let cr4: usize;
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        VmcsField::HostCr0.vmwrite(cr0)?;
        VmcsField::HostCr3.vmwrite(cr3)?;
        VmcsField::HostCr4.vmwrite(cr4)
    }
}

/// Use this to dump the state.
/// TODO: make this whole thing cleaner. We have duplicated code.
pub fn dump_host_state<'vmx>(
    _vmcs: &mut ActiveVmcs<'vmx>,
    values: &mut [usize; 13],
) -> Result<(), VmxError> {
    // NOTE: See section 24.5 of volume 3C.
    unsafe {
        values[0] = VmcsField::HostCsSelector.vmread()?;
        values[1] = VmcsField::HostDsSelector.vmread()?;
        values[2] = VmcsField::HostEsSelector.vmread()?;
        values[3] = VmcsField::HostFsSelector.vmread()?;
        values[4] = VmcsField::HostGsSelector.vmread()?;
        values[5] = VmcsField::HostSsSelector.vmread()?;
        values[6] = VmcsField::HostTrSelector.vmread()?;
        values[7] = VmcsField::HostIdtrBase.vmread()?;
        values[8] = VmcsField::HostGdtrBase.vmread()?;
        values[9] = VmcsField::HostIa32Efer.vmread()?;
        values[10] = VmcsField::HostCr0.vmread()?;
        values[11] = VmcsField::HostCr3.vmread()?;
        values[12] = VmcsField::HostCr4.vmread()?;
    }
    Ok(())
}

/// Saves the host state (control registers, segments...), so that they are restored on VM Exit.
pub fn load_host_state<'vmx>(
    _vmcs: &mut ActiveVmcs<'vmx>,
    values: &mut [usize; 13],
) -> Result<(), VmxError> {
    // NOTE: See section 24.5 of volume 3C.
    unsafe {
        VmcsField::HostCsSelector.vmwrite(values[0])?;
        VmcsField::HostDsSelector.vmwrite(values[1])?;
        VmcsField::HostEsSelector.vmwrite(values[2])?;
        VmcsField::HostFsSelector.vmwrite(values[3])?;
        VmcsField::HostGsSelector.vmwrite(values[4])?;
        VmcsField::HostSsSelector.vmwrite(values[5])?;
        VmcsField::HostTrSelector.vmwrite(values[6])?;
        VmcsField::HostIdtrBase.vmwrite(values[7])?;
        VmcsField::HostGdtrBase.vmwrite(values[8])?;
        VmcsField::HostIa32Efer.vmwrite(values[9])?;
        VmcsField::HostCr0.vmwrite(values[10])?;
        VmcsField::HostCr3.vmwrite(values[11])?;
        VmcsField::HostCr4.vmwrite(values[12])
    }
}
