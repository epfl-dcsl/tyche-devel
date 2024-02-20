//! Guest VMX utils

use core::arch::asm;

use stage_two_abi::GuestInfo;
use vmx::fields::VmcsField;
use vmx::{msr, ActiveVmcs, VmxError};
use x86_64::instructions::tables::{sgdt, sidt};
use x86_64::registers::model_specific::Efer;
use x86_64::registers::segmentation;
use x86_64::registers::segmentation::Segment;

use crate::cpu;

pub fn save_host_info(info: &mut GuestInfo) {
    info.cs = segmentation::CS::get_reg().0;
    info.ds = segmentation::DS::get_reg().0;
    info.es = segmentation::ES::get_reg().0;
    info.fs = segmentation::FS::get_reg().0;
    info.gs = segmentation::GS::get_reg().0;
    info.ss = segmentation::SS::get_reg().0;
    info.efer = Efer::read().bits();
}

/// Saves the host state (control registers, segments...), so that they are restored on VM Exit.
pub fn save_host_state<'vmx>(_vmcs: &mut ActiveVmcs<'vmx>) -> Result<(), VmxError> {
    // NOTE: See section 24.5 of volume 3C.

    // Segments
    let cs = segmentation::CS::get_reg();
    let ds = segmentation::DS::get_reg();
    let es = segmentation::ES::get_reg();
    let fs = segmentation::FS::get_reg();
    let gs = segmentation::GS::get_reg();
    let ss = segmentation::SS::get_reg();
    let tr: u16;
    let gdt = sgdt();
    let idt = sidt();

    unsafe {
        // There is no nice wrapper to read `tr` in the x86_64 crate.
        asm!("str {0:x}",
                out(reg) tr,
                options(att_syntax, nostack, nomem, preserves_flags));
    }

    unsafe {
        VmcsField::HostCsSelector.vmwrite(cs.0 as usize)?;
        VmcsField::HostDsSelector.vmwrite(ds.0 as usize)?;
        VmcsField::HostEsSelector.vmwrite(es.0 as usize)?;
        VmcsField::HostFsSelector.vmwrite(fs.0 as usize)?;
        VmcsField::HostGsSelector.vmwrite(gs.0 as usize)?;
        VmcsField::HostSsSelector.vmwrite(ss.0 as usize)?;
        VmcsField::HostTrSelector.vmwrite(tr as usize)?;

        // NOTE: those might throw an exception depending on the CPU features, let's just
        // ignore them for now.
        // VmcsHostStateNat::FsBase.vmwrite(FS::read_base().as_u64() as usize)?;
        // VmcsHostStateNat::GsBase.vmwrite(GS::read_base().as_u64() as usize)?;

        VmcsField::HostIdtrBase.vmwrite(idt.base.as_u64() as usize)?;
        VmcsField::HostGdtrBase.vmwrite(gdt.base.as_u64() as usize)?;

        // Save TR base
        let tr_offset = (tr >> 3) as usize;
        let gdt = cpu::current().as_mut().unwrap().gdt().gdt.as_raw_slice();
        let low = gdt[tr_offset];
        let high = gdt[tr_offset + 1];
        let tr_base = get_tr_base(high, low);
        VmcsField::HostTrBase.vmwrite(tr_base as usize)?;
    }

    // MSRs
    unsafe {
        VmcsField::HostIa32SysenterEsp.vmwrite(msr::SYSENTER_ESP.read() as usize)?;
        VmcsField::HostIa32SysenterEip.vmwrite(msr::SYSENTER_EIP.read() as usize)?;
        VmcsField::HostIa32SysenterCs.vmwrite(msr::SYSENTER_CS.read() as usize)?;
        VmcsField::HostIa32Efer.vmwrite(Efer::read().bits() as usize)?;
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

// ———————————————————————————— Helper Functions ———————————————————————————— //

/// Construct the TR base from its system segment descriptor.
///
/// See Intel manual 7.2.3.
fn get_tr_base(desc_high: u64, desc_low: u64) -> u64 {
    const BASE_2_MASK: u64 = ((1 << 8) - 1) << 24;
    const BASE_1_MASK: u64 = ((1 << 24) - 1) << 16;
    const LOW_32_BITS_MASK: u64 = (1 << 32) - 1;

    let mut ptr = 0;
    ptr |= (desc_high & LOW_32_BITS_MASK) << 32;
    ptr |= (desc_low & BASE_2_MASK) >> 32;
    ptr |= (desc_low & BASE_1_MASK) >> 16;
    ptr
}
