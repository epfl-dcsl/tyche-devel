//! VMX guest backend

use core::arch::asm;

use capa_engine::{Bitmaps, Domain, Handle, LocalCapa, NextCapaToken};
use vmx::bitmaps::exit_qualification;
use vmx::errors::Trapnr;
use vmx::{
    ActiveVmcs, ControlRegister, InterruptionType, Register, VmExitInterrupt, VmxExitReason, Vmxon,
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

/// VMXState encapsulates the vmxon and current vcpu.
/// The vcpu is subject to changes, but the vmxon remains the same
/// for the entire execution.
pub struct VmxState {
    pub vcpu: ActiveVmcs<'static>,
    pub vmxon: Vmxon,
}

pub fn main_loop(mut vmx_state: VmxState, mut domain: Handle<Domain>) {
    let core_id = cpuid();
    let mut result = unsafe { vmx_state.vcpu.run() };
    loop {
        let exit_reason = match result {
            Ok(exit_reason) => {
                let res = handle_exit(&mut vmx_state, exit_reason, &mut domain)
                    .expect("Failed to handle VM exit");

                // Apply core-local updates before returning
                monitor::apply_core_updates(&mut vmx_state, &mut domain, core_id);

                res
            }
            Err(err) => {
                log::error!("Guest crash: {:?}", err);
                log::error!("Vcpu: {:x?}", vmx_state.vcpu);
                HandlerResult::Crash
            }
        };

        match exit_reason {
            HandlerResult::Resume => {
                result = unsafe { vmx_state.vcpu.run() };
            }
            _ => {
                log::info!("Exiting guest: {:?}", exit_reason);
                break;
            }
        }
    }
}

fn handle_exit(
    vs: &mut VmxState,
    reason: vmx::VmxExitReason,
    domain: &mut Handle<Domain>,
) -> Result<HandlerResult, TycheError> {
    //let vcpu = &mut vmx_state.vcpu;
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
            let vmcall = vs.vcpu.get(Register::Rax) as usize;
            let arg_1 = vs.vcpu.get(Register::Rdi) as usize;
            let arg_2 = vs.vcpu.get(Register::Rsi) as usize;
            let arg_3 = vs.vcpu.get(Register::Rdx) as usize;
            let arg_4 = vs.vcpu.get(Register::Rcx) as usize;
            let arg_5 = vs.vcpu.get(Register::R8) as usize;
            let arg_6 = vs.vcpu.get(Register::R9) as usize;
            match vmcall {
                calls::CREATE_DOMAIN => {
                    log::trace!("Create Domain");
                    let capa = monitor::do_create_domain(*domain).expect("TODO");
                    vs.vcpu.set(Register::Rdi, capa.as_u64());
                    vs.vcpu.set(Register::Rax, 0);
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::CONFIGURE => {
                    log::trace!("Configure");
                    if let Ok(bitmap) = Bitmaps::from_usize(arg_1) {
                        match monitor::do_set_config(
                            *domain,
                            LocalCapa::new(arg_2),
                            bitmap,
                            arg_3 as u64,
                        ) {
                            Ok(_) => {
                                // Check if we need to initialize context.
                                if bitmap == Bitmaps::SWITCH {
                                    monitor::do_init_child_contexts(
                                        *domain,
                                        LocalCapa::new(arg_2),
                                        &mut vs.vcpu,
                                    )
                                }
                                vs.vcpu.set(Register::Rax, 0);
                            }
                            Err(e) => {
                                log::error!("Configuration error: {:?}", e);
                                vs.vcpu.set(Register::Rax, 1);
                            }
                        }
                    } else {
                        log::error!("Invalid configuration target");
                        vs.vcpu.set(Register::Rax, 1);
                    }
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SET_ENTRY_ON_CORE => {
                    log::trace!(
                        "Set entry on core {}, cr3 {:x}, rip {:x}, rsp {:x}",
                        arg_2,
                        arg_3,
                        arg_4,
                        arg_5
                    );
                    match monitor::do_set_entry(
                        *domain,
                        LocalCapa::new(arg_1),
                        arg_2, // core
                        arg_3, // cr3
                        arg_4, // rip
                        arg_5, // rsp
                    ) {
                        Ok(()) => vs.vcpu.set(Register::Rax, 0),
                        Err(e) => {
                            log::error!("Unable to set entry: {:?}", e);
                            vs.vcpu.set(Register::Rax, 1);
                        }
                    }
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SEAL_DOMAIN => {
                    log::trace!("Seal Domain");
                    let capa = monitor::do_seal(*domain, LocalCapa::new(arg_1)).expect("TODO");
                    vs.vcpu.set(Register::Rdi, capa.as_u64());
                    vs.vcpu.set(Register::Rax, 0);
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SHARE => {
                    log::trace!("Share");
                    log::warn!("Share is NOT IMPLEMENTED in v3");
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SEND => {
                    log::trace!("Send");
                    monitor::do_send(*domain, LocalCapa::new(arg_1), LocalCapa::new(arg_2))
                        .expect("TODO");
                    vs.vcpu.set(Register::Rax, 0);
                    vs.vcpu.next_instruction()?;
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
                    vs.vcpu.set(Register::Rdi, left.as_u64());
                    vs.vcpu.set(Register::Rsi, right.as_u64());
                    vs.vcpu.set(Register::Rax, 0);
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::REVOKE => {
                    log::trace!("Revoke");
                    monitor::do_revoke(*domain, LocalCapa::new(arg_1)).expect("TODO");
                    vs.vcpu.set(Register::Rax, 0);
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::DUPLICATE => {
                    log::trace!("Duplicate");
                    let capa = monitor::do_duplicate(*domain, LocalCapa::new(arg_1)).expect("TODO");
                    vs.vcpu.set(Register::Rdi, capa.as_u64());
                    vs.vcpu.set(Register::Rax, 0);
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::ENUMERATE => {
                    log::trace!("Enumerate");
                    if let Some((info, next)) =
                        monitor::do_enumerate(*domain, NextCapaToken::from_usize(arg_1))
                    {
                        let (v1, v2, v3) = info.serialize();
                        vs.vcpu.set(Register::Rdi, v1 as u64);
                        vs.vcpu.set(Register::Rsi, v2 as u64);
                        vs.vcpu.set(Register::Rdx, v3 as u64);
                        vs.vcpu.set(Register::Rcx, next.as_u64());
                    } else {
                        // For now, this marks the end
                        vs.vcpu.set(Register::Rcx, 0);
                    }
                    vs.vcpu.set(Register::Rax, 0);
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SWITCH => {
                    log::trace!("Switch");
                    monitor::do_switch(*domain, LocalCapa::new(arg_1), cpuid()).expect("TODO");
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::DEBUG => {
                    log::trace!("Debug");
                    monitor::do_debug();
                    vs.vcpu.set(Register::Rax, 0);
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::EXIT => {
                    log::info!("MonCall: exit");
                    dump(&mut vs.vcpu);
                    Ok(HandlerResult::Exit)
                }
                _ => {
                    log::info!("Unknown MonCall: 0x{:x}", vmcall);
                    todo!("Unknown VMCall");
                }
            }
        }
        VmxExitReason::Cpuid => {
            let input_eax = vs.vcpu.get(Register::Rax);
            let input_ecx = vs.vcpu.get(Register::Rcx);
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

            vs.vcpu.set(Register::Rax, eax);
            vs.vcpu.set(Register::Rbx, ebx);
            vs.vcpu.set(Register::Rcx, ecx);
            vs.vcpu.set(Register::Rdx, edx);
            vs.vcpu.next_instruction()?;
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::ControlRegisterAccesses => {
            let qualification = vs.vcpu.exit_qualification()?.control_register_accesses();
            match qualification {
                exit_qualification::ControlRegisterAccesses::MovToCr(cr, reg) => {
                    if cr != ControlRegister::Cr4 {
                        todo!("Handle {:?}", cr);
                    }
                    let value = vs.vcpu.get(reg) as usize;
                    vs.vcpu.set_cr4_shadow(value)?;
                    let real_value = value | (1 << 13); // VMXE
                    vs.vcpu.set_cr(cr, real_value);

                    vs.vcpu.next_instruction()?;
                }
                _ => todo!("Emulation not yet implemented for {:?}", qualification),
            };
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::EptViolation => {
            let addr = vs.vcpu.guest_phys_addr()?;
            log::error!(
                "EPT Violation! virt: 0x{:x}, phys: 0x{:x}",
                vs.vcpu
                    .guest_linear_addr()
                    .expect("unable to get the virt addr")
                    .as_u64(),
                addr.as_u64(),
            );
            log::info!("The vcpu {:x?}", vs.vcpu);

            //TODO: replace this with proper handler for interrupts.
            if domain.idx() == 0 {
                let interrupt = VmExitInterrupt::create(
                    Trapnr::Breakpoint,
                    InterruptionType::SoftwareException,
                    None,
                    vcpu,
                );
                // Inject the interrupt.
                log::debug!(
                    "Replace EPT violation with exception: {:b}",
                    interrupt.as_u32()
                );
                vs.vcpu
                    .inject_interrupt(interrupt)
                    .expect("Unable to inject an exception");
                return Ok(HandlerResult::Resume);
            }
            Ok(HandlerResult::Crash)
        }
        VmxExitReason::Xsetbv => {
            let ecx = vs.vcpu.get(Register::Rcx);
            let eax = vs.vcpu.get(Register::Rax);
            let edx = vs.vcpu.get(Register::Rdx);

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

            vs.vcpu.next_instruction()?;
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::Wrmsr => {
            let ecx = vs.vcpu.get(Register::Rcx);
            if ecx >= 0x4B564D00 && ecx <= 0x4B564DFF {
                // Custom MSR range, used by KVM
                // See https://docs.kernel.org/virt/kvm/x86/msr.html
                // TODO: just ignore them for now, should add support in the future
                vs.vcpu.next_instruction()?;
                Ok(HandlerResult::Resume)
            } else {
                log::error!("Unknown MSR: 0x{:x}", ecx);
                Ok(HandlerResult::Crash)
            }
        }
        VmxExitReason::Rdmsr => {
            let ecx = vs.vcpu.get(Register::Rcx);
            if ecx == 0xc0011029 {
                // Reading an AMD specifig register, just ignore it
                vs.vcpu.next_instruction()?;
                Ok(HandlerResult::Resume)
            } else {
                log::error!("Unexpected rdmsr number: {:#x}", ecx);
                Ok(HandlerResult::Crash)
            }
        }
        VmxExitReason::Exception => {
            match vs.vcpu.interrupt_info() {
                Ok(Some(exit)) => {
                    // The domain exited, so it shouldn't be able to handle it.
                    log::debug!(
                        "EXCEPTION RECEIVED {:b}, vector: {:?}, type: {:?}",
                        exit.as_u32(),
                        exit.vector(),
                        exit.interrupt_type()
                    );
                    match monitor::handle_trap(*domain, cpuid(), exit) {
                        Ok(()) => {
                            log::debug!("Received exception {}, re-routing it", exit.vector());
                            Ok(HandlerResult::Resume)
                        }
                        Err(e) => {
                            log::error!(
                                "Unable to handle the exception {}, capa error:{:?}",
                                exit.vector(),
                                e
                            );
                            log::error!("{:?}", vs.vcpu);
                            Ok(HandlerResult::Crash)
                        }
                    }
                }
                _ => {
                    log::error!("VM received an exception");
                    log::info!("{:?}", vs.vcpu);
                    Ok(HandlerResult::Crash)
                }
            }
        }
        _ => {
            log::error!(
                "Emulation is not yet implemented for exit reason: {:?}",
                reason
            );
            log::info!("{:?}", vs.vcpu);
            Ok(HandlerResult::Crash)
        }
    }
}
