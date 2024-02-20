//! Raw VMX operations
//!
//! This modules exposes low-level VMX functionalities. The functions here are marked as unsafe
//! because they do not verify the validity of input arguments or processor state. This module is
//! intended to be used through higher-level wrappers that provide more safety through typing.

use core::arch::asm;

use crate::bitmaps::RFlags;
use crate::errors::{VmxError, VmxInstructionError};
use crate::fields::{GeneralPurposeField as GPF, VmcsField, REGFILE_SIZE};
use crate::ActiveVmcs;

/// Executes VMXON.
///
/// `addr` must be the physical address of a page-aligned region large enough to contain a VMXON
/// region.
pub unsafe fn vmxon(addr: u64) -> Result<(), VmxError> {
    asm!("vmxon ({0})", in(reg) &addr, options(att_syntax));
    vmx_capture_status()
}

/// Executes VMXOFF.
///
/// The processor must be in VMX operation mode, and will have exited that mode if the operation
/// succeeds.
pub unsafe fn vmxoff() -> Result<(), VmxError> {
    asm!("vmxoff");
    vmx_capture_status()
}

/// Executes VMCLEAR.
///
/// This will clear the VMCS at the provided physical address.
pub unsafe fn vmclear(addr: u64) -> Result<(), VmxError> {
    asm! {"vmclear ({0})", in(reg) &addr, options(att_syntax)};
    vmx_capture_status()
}

/// Executes VMWRITE.
///
/// This will write the value to the current VMCS in the provided field.
pub unsafe fn vmwrite(field: u64, value: u64) -> Result<(), VmxError> {
    asm!("vmwrite {1}, {0}", in(reg) field, in(reg) value, options(att_syntax));
    vmx_capture_status()
}

/// Executes VMREAD.
///
/// This will read a field from the current VMCS and return its value.
pub unsafe fn vmread(field: u64) -> Result<u64, VmxError> {
    let value: u64;
    asm!("vmread {0}, {1}", in(reg) field, out(reg) value, options(att_syntax));
    vmx_capture_status().and(Ok(value))
}

/// Executes VMPTRLD.
///
/// This loads a VMCS and mark it as active. All further VMWRITE and VMREAD operations will operate
/// on this VMCS until it is replaced.
pub unsafe fn vmptrld(addr: u64) -> Result<(), VmxError> {
    asm!("vmptrld ({0})", in(reg) &addr, options(att_syntax));
    vmx_capture_status()
}

pub unsafe fn vmptrst() -> Result<u64, VmxError> {
    let value: u64 = 0;
    asm!(
        "vmptrst ({0})",       // Read vmptr into rax register
        in(reg) &value ,     // Output constraint for vmptr
        options(att_syntax)
    );
    vmx_capture_status().and(Ok(value))
}

/// Save host state, restore guest state and executes VMLAUNCH.
///
/// On success, this will switch to non-root mode and load guest state from current VMCS and return
/// the exit reason.
///
/// # SAFETY:
/// - If the guest is not properly loaded, configured, and sandboxed, this might result in
///   arbitrary execution.
/// - This function expects a 64 bits architecture for now.
pub unsafe fn vmlaunch(
    _vmcs: &mut ActiveVmcs,
    regs: &mut [usize; REGFILE_SIZE],
) -> Result<(), VmxError> {
    let rip_field = VmcsField::HostRip as u64;
    let rsp_field = VmcsField::HostRsp as u64;
    // Start by switching lstar IF needed.
    //let lstar = msr::Msr::new(IA32_LSTAR.address()).read();
    //msr::Msr::new(IA32_LSTAR.address()).write(regs[GPF::Lstar as usize] as u64);
    let vcpu_ptr = regs.as_mut_ptr();
    asm!(
        // Save some of the host state on the stack
        "push rbx",                   // Save %rbx, see https://stackoverflow.com/a/71481425
        "push rbp",                   // Save %rbp
        "push rax",                   // Save %rax (vcpu pointer)

        // Save remaining host state to VMCS
        "vmwrite rcx, rsp",           // Write %rsp to VMCS
        "lea rbp, [rip + 25]",        // Compute the address of the next instruction after vmlaunch
        "vmwrite rdx, rbp",           // Write tha value to VMCS

        // Restore guest registers
        "mov rbx, [rax + 8]",         // Restore guest %rbx
        "mov rcx, [rax + 16]",        // Restore guest %rcx
        "mov rdx, [rax + 24]",        // Restore guest %rdx
        "mov rbp, [rax + 32]",        // Restore guest %rbp
        "mov rax, [rax]",             // Restore guest %rdx

        // Launch VM
        "vmlaunch",                   // Launch the VM
        "nop",                        // After VM Exit we land here

        // Save guest registers
        "push rbx",                   // Save guest %rbx
        "mov rbx, [rsp + 8]",         // Load vcpu pointer (second value from top of the stack)
        "mov [rbx + 32], rbp",        // Save guest %rbp to vcpu
        "pop rbp",                    // Load guest %rbx in %rbp
        "mov [rbx + 8], rbp",         // Save guest %rbx to vcpu

        // Restore host registers
        "pop rbx",                    // Discard pointer to vcpu
        "pop rbp",                    // Restore %rbp
        "pop rbx",                    // Restore %rbx

        // Registers used
        inout("rax") vcpu_ptr => regs[GPF::Rax as usize],     // VCPU RBX pointer
        inout("rcx") rsp_field => regs[GPF::Rcx as usize],    // RSP host VMCS field
        inout("rdx") rip_field => regs[GPF::Rdx as usize],    // RIP host VMCS field

        // Register automatically loaded and restored
        inout("rsi") regs[GPF::Rsi as usize] => regs[GPF::Rsi as usize],
        inout("rdi") regs[GPF::Rdi as usize] => regs[GPF::Rdi as usize],
        inout("r8")  regs[GPF::R8  as usize] => regs[GPF::R8  as usize],
        inout("r9")  regs[GPF::R9  as usize] => regs[GPF::R9  as usize],
        inout("r10") regs[GPF::R10 as usize] => regs[GPF::R10 as usize],
        inout("r11") regs[GPF::R11 as usize] => regs[GPF::R11 as usize],
        inout("r12") regs[GPF::R12 as usize] => regs[GPF::R12 as usize],
        inout("r13") regs[GPF::R13 as usize] => regs[GPF::R13 as usize],
        inout("r14") regs[GPF::R14 as usize] => regs[GPF::R14 as usize],
        inout("r15") regs[GPF::R15 as usize] => regs[GPF::R15 as usize],
    );
    // NOTE: it is correct to check the flag even after a nop and pop instructions since none of
    // them modifies any flags.
    let res = vmx_capture_status();
    // Save the current lstar IF NEEDED.
    //regs[GPF::Lstar as usize] = msr::Msr::new(IA32_LSTAR.address()).read() as usize;
    // Restore Lstar.
    //msr::Msr::new(IA32_LSTAR.address()).write(lstar);
    res
}

/// Save host state, restore guest state and executes VMRESUME.
///
/// On success, this will switch to non-root mode and load guest state from current VMCS and return
/// the exit reason.
///
/// # SAFETY:
/// - If the guest is not properly loaded, configured, and sandboxed, this might result in
///   arbitrary execution.
/// - This function expects a 64 bits architecture for now.
pub unsafe fn vmresume(
    _vmcs: &mut ActiveVmcs,
    regs: &mut [usize; REGFILE_SIZE],
) -> Result<(), VmxError> {
    let rip_field = VmcsField::HostRip as u64;
    let rsp_field = VmcsField::HostRsp as u64;
    // TODO Start by switching lstar IF needed.
    //let lstar = msr::Msr::new(IA32_LSTAR.address()).read();
    //msr::Msr::new(IA32_LSTAR.address()).write(regs[GPF::Lstar as usize] as u64);
    let vcpu_ptr = regs.as_mut_ptr();
    asm!(
        // Save some of the host state on the stack
        "push rbx",                   // Save %rbx, see https://stackoverflow.com/a/71481425
        "push rbp",                   // Save %rbp
        "push rax",                   // Save %rax (vcpu pointer)

        // Save remaining host state to VMCS
        "vmwrite rcx, rsp",           // Write %rsp to VMCS
        "lea rbp, [rip + 25]",        // Compute the address of the next instruction after vmlaunch
        "vmwrite rdx, rbp",           // Write that value to VMCS

        // Restore guest registers
        "mov rbx, [rax + 8]",         // Restore guest %rbx
        "mov rcx, [rax + 16]",        // Restore guest %rcx
        "mov rdx, [rax + 24]",        // Restore guest %rdx
        "mov rbp, [rax + 32]",        // Restore guest %rbp
        "mov rax, [rax]",             // Restore guest %rdx

        // Launch VM
        "vmresume",                   // Resume the VM
        "nop",                        // After VM Exit we land here

        // Save guest registers
        "push rbx",                   // Save guest %rbx
        "mov rbx, [rsp + 8]",         // Load vcpu pointer (second value from top of the stack)
        "mov [rbx + 32], rbp",        // Save guest %rbp to vcpu
        "pop rbp",                    // Load guest %rbx in %rbp
        "mov [rbx + 8], rbp",         // Save guest %rbx to vcpu

        // Restore host registers
        "pop rbx",                    // Discard pointer to vcpu
        "pop rbp",                    // Restore %rbp
        "pop rbx",                    // Restore %rbx

        // Registers used
        inout("rax") vcpu_ptr => regs[GPF::Rax as usize],     // VCPU RBX pointer
        inout("rcx") rsp_field => regs[GPF::Rcx as usize],    // RSP host VMCS field
        inout("rdx") rip_field => regs[GPF::Rdx as usize],    // RIP host VMCS field

        // Register automatically loaded and restored
        inout("rsi") regs[GPF::Rsi as usize] => regs[GPF::Rsi as usize],
        inout("rdi") regs[GPF::Rdi as usize] => regs[GPF::Rdi as usize],
        inout("r8")  regs[GPF::R8  as usize] => regs[GPF::R8  as usize],
        inout("r9")  regs[GPF::R9  as usize] => regs[GPF::R9  as usize],
        inout("r10") regs[GPF::R10 as usize] => regs[GPF::R10 as usize],
        inout("r11") regs[GPF::R11 as usize] => regs[GPF::R11 as usize],
        inout("r12") regs[GPF::R12 as usize] => regs[GPF::R12 as usize],
        inout("r13") regs[GPF::R13 as usize] => regs[GPF::R13 as usize],
        inout("r14") regs[GPF::R14 as usize] => regs[GPF::R14 as usize],
        inout("r15") regs[GPF::R15 as usize] => regs[GPF::R15 as usize],
    );

    // NOTE: it is correct to check the flag even after a nop and pop instructions since none of
    // them modifies any flags.
    let res = vmx_capture_status();
    // TODO: Save the current lstar IF NEEDED.
    //regs[GPF::Lstar as usize] = msr::Msr::new(IA32_LSTAR.address()).read() as usize;
    // Restore the previous lstar.
    //msr::Msr::new(IA32_LSTAR.address()).write(lstar);
    res
}

/// Helper used to extract VMX-specific Result in accordance with
/// conventions described in Intel SDM, Volume 3C, Section 30.2.
//  We inline this to provide an obstruction-free path from this function's
//  call site to the moment where `rflags::read()` reads RFLAGS. Otherwise it's
//  possible for RFLAGS register to be clobbered by a function prologue,
//  see https://github.com/gz/rust-x86/pull/50.
#[inline(always)]
pub(crate) unsafe fn vmx_capture_status() -> Result<(), VmxError> {
    let flags = rflags_read();

    if flags.contains(RFlags::ZERO_FLAG) {
        // A valid VMCS is installed, we can read the error field
        let instr_err_field = VmcsField::VmInstructionError as u64;
        let err: u64;
        asm!("vmread {0}, {1}", in(reg) instr_err_field, out(reg) err, options(att_syntax));
        let flags = rflags_read();
        let error = if flags.intersects(RFlags::ZERO_FLAG | RFlags::CARRY_FLAG) {
            // An error occured during VMREAD
            VmxInstructionError::Unknown
        } else {
            VmxInstructionError::from_u64(err)
        };

        Err(VmxError::VmFailValid(error))
    } else if flags.contains(RFlags::CARRY_FLAG) {
        Err(VmxError::VmFailInvalid)
    } else {
        Ok(())
    }
}

/// Returns the current value of the RFLAGS register.
///
/// NOTE: We redefine this function here with an inline(always) hint so that it is always inlined
/// which prevent the flags from being clobbered by function calls.
#[inline(always)]
fn rflags_read() -> RFlags {
    let r: u64;

    unsafe {
        asm!("pushfq; pop {}", out(reg) r, options(nomem, preserves_flags));
    }
    RFlags::from_bits_truncate(r)
}
