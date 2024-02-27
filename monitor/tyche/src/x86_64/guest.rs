//! VMX guest backend

use core::arch::asm;

use capa_engine::{Domain, Handle, LocalCapa, NextCapaToken};
use vmx::bitmaps::exit_qualification;
use vmx::errors::Trapnr;
use vmx::{
    msr, ActiveVmcs, ControlRegister, InterruptionType, Register, VmExitInterrupt, VmxExitReason,
};

use super::{cpuid, monitor};
use crate::calls;
use crate::error::TycheError;

#[derive(PartialEq, Debug)]
pub enum HandlerResult {
    Resume,
    Exit,
    Crash,
}

pub fn main_loop(mut vcpu: ActiveVmcs<'static>, mut domain: Handle<Domain>) {
    let core_id = cpuid();
    let mut result = unsafe { vcpu.launch() };
    loop {
        let exit_reason = match result {
            Ok(exit_reason) => {
                let res = handle_exit(&mut vcpu, exit_reason, &mut domain)
                    .expect("Failed to handle VM exit");

                // Apply core-local updates before returning
                monitor::apply_core_updates(&mut vcpu, &mut domain, core_id);

                res
            }
            Err(err) => {
                log::error!("Guest crash: {:?}", err);
                HandlerResult::Crash
            }
        };

        if exit_reason != HandlerResult::Resume {
            log::info!("Exiting guest: {:?}", exit_reason);
            break;
        }
        // Resume VM
        result = unsafe { vcpu.resume() };
    }
}

fn handle_exit(
    vcpu: &mut ActiveVmcs<'static>,
    reason: vmx::VmxExitReason,
    domain: &mut Handle<Domain>,
) -> Result<HandlerResult, TycheError> {
    let dump = |vcpu: &mut ActiveVmcs| {
        let rip = vcpu.get(Register::Rip);
        let rax = vcpu.get(Register::Rax);
        let rcx = vcpu.get(Register::Rcx);
        let rbp = vcpu.get(Register::Rbp);
        log::info!(
            "VM Exit: {:?} - rip: 0x{:x} - rbp: 0x{:x} - rax: 0x{:x} - rcx: 0x{:x}",
            reason,
            rip,
            rbp,
            rax,
            rcx
        );
    };

    match reason {
        VmxExitReason::Vmcall => {
            let vmcall = vcpu.get(Register::Rax) as usize;
            let arg_1 = vcpu.get(Register::Rdi) as usize;
            let arg_2 = vcpu.get(Register::Rsi) as usize;
            let arg_3 = vcpu.get(Register::Rdx) as usize;
            let arg_4 = vcpu.get(Register::Rcx) as usize;
            let arg_5 = vcpu.get(Register::R8) as usize;
            let arg_6 = vcpu.get(Register::R9) as usize;
            match vmcall {
                calls::CREATE_DOMAIN => {
                    log::trace!("Create Domain");
                    let capa = monitor::do_create_domain(*domain).expect("TODO");
                    vcpu.set(Register::Rdi, capa.as_u64());
                    vcpu.set(Register::Rax, 0);
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SEAL_DOMAIN => {
                    log::trace!("Seal Domain");
                    let capa =
                        monitor::do_seal(*domain, LocalCapa::new(arg_1), arg_2, arg_3, arg_4)
                            .expect("TODO");
                    vcpu.set(Register::Rdi, capa.as_u64());
                    vcpu.set(Register::Rax, 0);
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SHARE => {
                    log::trace!("Share");
                    log::warn!("Share is NOT IMPLEMENTED in v3");
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SEND => {
                    log::trace!("Send");
                    monitor::do_send(*domain, LocalCapa::new(arg_1), LocalCapa::new(arg_2))
                        .expect("TODO");
                    vcpu.set(Register::Rax, 0);
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SEGMENT_REGION => {
                    log::trace!("Segment region");
                    let (left, right) = monitor::do_segment_region(
                        *domain,
                        LocalCapa::new(arg_1),
                        arg_2,               // start
                        arg_3,               // end
                        arg_6 >> 32,         // prot1
                        arg_4,               // start
                        arg_5,               // end
                        (arg_6 << 32) >> 32, // prot2
                    )
                    .expect("TODO");
                    vcpu.set(Register::Rdi, left.as_u64());
                    vcpu.set(Register::Rsi, right.as_u64());
                    vcpu.set(Register::Rax, 0);
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::REVOKE => {
                    log::trace!("Revoke");
                    monitor::do_revoke(*domain, LocalCapa::new(arg_1)).expect("TODO");
                    vcpu.set(Register::Rax, 0);
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::DUPLICATE => {
                    log::trace!("Duplicate");
                    let capa = monitor::do_duplicate(*domain, LocalCapa::new(arg_1)).expect("TODO");
                    vcpu.set(Register::Rdi, capa.as_u64());
                    vcpu.set(Register::Rax, 0);
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::ENUMERATE => {
                    log::trace!("Enumerate");
                    if let Some((info, next)) =
                        monitor::do_enumerate(*domain, NextCapaToken::from_usize(arg_1))
                    {
                        let (v1, v2, v3) = info.serialize();
                        vcpu.set(Register::Rdi, v1 as u64);
                        vcpu.set(Register::Rsi, v2 as u64);
                        vcpu.set(Register::Rdx, v3 as u64);
                        vcpu.set(Register::Rcx, next.as_u64());
                    } else {
                        // For now, this marks the end
                        vcpu.set(Register::Rcx, 0);
                    }
                    vcpu.set(Register::Rax, 0);
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SWITCH => {
                    log::trace!("Switch");
                    monitor::do_switch(*domain, LocalCapa::new(arg_1), cpuid()).expect("TODO");
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::DEBUG => {
                    log::trace!("Debug");
                    monitor::do_debug();
                    vcpu.set(Register::Rax, 0);
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::EXIT => {
                    log::info!("MonCall: exit");
                    dump(vcpu);
                    Ok(HandlerResult::Exit)
                }
                _ => {
                    log::info!("Unknown MonCall: 0x{:x}", vmcall);
                    todo!("Unknown VMCall");
                }
            }
        }
        VmxExitReason::InitSignal => {
            log::info!(
                "CPU{} received InitSignal RIP={:#x}",
                cpuid(),
                vcpu.get(Register::Rip)
            );
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::Cpuid => {
            let input_eax = vcpu.get(Register::Rax);
            let input_ecx = vcpu.get(Register::Rcx);
            let eax: u64;
            let ebx: u64;
            let ecx: u64;
            let edx: u64;

            unsafe {
                // Note: LLVM reserves %rbx for its internal use, so we need to use a scratch
                // register for %rbx here.
                asm!(
                    "mov {tmp}, rbx",
                    "cpuid",
                    "mov rsi, rbx",
                    "mov rbx, {tmp}",
                    tmp = out(reg) _,
                    inout("rax") input_eax => eax,
                    inout("rcx") input_ecx => ecx,
                    out("rdx") edx,
                    out("rsi") ebx
                )
            }

            vcpu.set(Register::Rax, eax);
            vcpu.set(Register::Rbx, ebx);
            vcpu.set(Register::Rcx, ecx);
            vcpu.set(Register::Rdx, edx);
            vcpu.next_instruction()?;
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::ControlRegisterAccesses => {
            let qualification = vcpu.exit_qualification()?.control_register_accesses();
            match qualification {
                exit_qualification::ControlRegisterAccesses::MovToCr(cr, reg) => {
                    if cr != ControlRegister::Cr4 {
                        todo!("Handle {:?}", cr);
                    }
                    let value = vcpu.get(reg) as usize;
                    vcpu.set_cr4_shadow(value)?;
                    let real_value = value | (1 << 13); // VMXE
                    vcpu.set_cr(cr, real_value);

                    vcpu.next_instruction()?;
                }
                _ => todo!("Emulation not yet implemented for {:?}", qualification),
            };
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::EptViolation => {
            let addr = vcpu.guest_phys_addr()?;
            log::error!(
                "EPT Violation! virt: 0x{:x}, phys: 0x{:x}",
                vcpu.guest_linear_addr()
                    .expect("unable to get the virt addr")
                    .as_u64(),
                addr.as_u64(),
            );
            log::info!("The vcpu {:x?}", vcpu);

            //TODO: replace this with proper handler for interrupts.
            if domain.idx() == 0 {
                let interrupt = VmExitInterrupt {
                    vector: Trapnr::PageFault.as_u8(),
                    int_type: InterruptionType::HardwareException,
                    error_code: None,
                };
                let flags = interrupt.as_injectable_u32();
                vcpu.set_vm_entry_interruption_information(flags)
                    .expect("Unable to inject an exception");
                return Ok(HandlerResult::Resume);
            }
            Ok(HandlerResult::Crash)
        }
        VmxExitReason::Xsetbv => {
            let ecx = vcpu.get(Register::Rcx);
            let eax = vcpu.get(Register::Rax);
            let edx = vcpu.get(Register::Rdx);

            let xrc_id = ecx & 0xFFFFFFFF; // Ignore 32 high-order bits
            if xrc_id != 0 {
                log::error!("Xsetbv: invalid rcx 0x{:x}", ecx);
                return Ok(HandlerResult::Crash);
            }

            unsafe {
                asm!(
                    "xsetbv",
                    in("ecx") ecx,
                    in("eax") eax,
                    in("edx") edx,
                );
            }

            vcpu.next_instruction()?;
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::Wrmsr => {
            let ecx = vcpu.get(Register::Rcx);

            if ecx == 0x832 || ecx == 0x838 || ecx == 0x839 || ecx == 0x83e {
                let mut msr = msr::Msr::new(ecx as u32);
                let rax = vcpu.get(Register::Rax);
                let rdx = vcpu.get(Register::Rdx);

                log::info!("rax={}, rdx={}", rax, rdx);

                // let low = value as u32;
                // let high = (value >> 32) as u32;
                unsafe { msr.write(((rdx as u64) << 32) | (rax as u64)) };

                // msr.read();
                Ok(HandlerResult::Resume)
            } else if ecx >= 0x4B564D00 && ecx <= 0x4B564DFF {
                // Custom MSR range, used by KVM
                // See https://docs.kernel.org/virt/kvm/x86/msr.html
                // TODO: just ignore them for now, should add support in the future
                vcpu.next_instruction()?;
                Ok(HandlerResult::Resume)
            } else {
                log::info!("Unknown MSR: 0x{:x}", ecx);
                Ok(HandlerResult::Crash)
            }
        }
        VmxExitReason::Rdmsr => {
            let ecx = vcpu.get(Register::Rcx);
            if ecx == 0x832 || ecx == 0x838 || ecx == 0x839 || ecx == 0x83e {
                let msr = msr::Msr::new(ecx as u32);
                // let rax = self.get(Register::Rax);
                // let rdx = self.get(Register::Rdx);
                // let low = value as u32;
                // let high = (value >> 32) as u32;
                let result = unsafe { msr.read() };
                log::info!("result={}", result);
                vcpu.set(Register::Rax, result);
                vcpu.set(Register::Rdx, result << 32);
            }
            log::info!("MSR: {:#x}", ecx);
            vcpu.next_instruction()?;
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::Exception => {
            match vcpu.interrupt_info() {
                Ok(Some(exit)) => {
                    log::info!("Exception: {:?}", vcpu.interrupt_info());
                    if exit.int_type == vmx::InterruptionType::HardwareException
                        && exit.vector == 14
                    {
                        // This is a page fault
                        log::info!(
                            "    Page fault at 0x{:x}",
                            vcpu.exit_qualification()
                                .expect("Missing VM Exit qualification")
                                .raw
                        );
                    }
                    log::error!("VM received an exception");
                    log::info!("{:?}", vcpu);
                    Ok(HandlerResult::Crash)
                    // Inject the fault back into the guest.
                    // let injection = exit.as_injectable_u32();
                    // vcpu.set_vm_entry_interruption_information(injection)?;
                    // Ok(HandlerResult::Resume)
                }
                _ => {
                    log::error!("VM received an exception");
                    log::info!("{:?}", vcpu);
                    Ok(HandlerResult::Crash)
                }
            }
        }
        _ => {
            log::error!(
                "Emulation is not yet implemented for exit reason: {:?}",
                reason
            );
            log::info!("{:?}", vcpu);
            Ok(HandlerResult::Crash)
        }
    }
}
