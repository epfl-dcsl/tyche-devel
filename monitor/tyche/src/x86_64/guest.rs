//! VMX guest backend

use core::arch::asm;

use capa_engine::{Bitmaps, Domain, Handle, LocalCapa, NextCapaToken};
use vmx::bitmaps::exit_qualification;
use vmx::fields::VmcsField;
use vmx::{ActiveVmcs, VmxExitReason, Vmxon};

use super::cpuid_filter::{filter_mpk, filter_tpause};
use super::{cpuid, monitor};
use crate::calls;
use crate::error::TycheError;
use crate::x86_64::filtered_fields::FilteredFields;
use crate::x86_64::platform;

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
    let mut result = unsafe {
        let mut context = monitor::get_context(domain, core_id);
        vmx_state.vcpu.run(&mut context.vmcs_gp)
    };
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
                log::error!("Domain: {:?}", domain);
                log::error!("Vcpu: {:x?}", vmx_state.vcpu);
                HandlerResult::Crash
            }
        };

        match exit_reason {
            HandlerResult::Resume => {
                result = unsafe {
                    let mut context = monitor::get_context(domain, core_id);
                    context.flush(&mut vmx_state.vcpu);
                    vmx_state.vcpu.run(&mut context.vmcs_gp)
                };
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
    match reason {
        VmxExitReason::Vmcall => {
            let (vmcall, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6) = {
                let mut context = monitor::get_context(*domain, cpuid());
                let vmcall = context.get(VmcsField::GuestRax, None)?;
                let arg_1 = context.get(VmcsField::GuestRdi, None)?;
                let arg_2 = context.get(VmcsField::GuestRsi, None)?;
                let arg_3 = context.get(VmcsField::GuestRdx, None)?;
                let arg_4 = context.get(VmcsField::GuestRcx, None)?;
                let arg_5 = context.get(VmcsField::GuestR8, None)?;
                let arg_6 = context.get(VmcsField::GuestR9, None)?;
                (vmcall, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6)
            };
            match vmcall {
                calls::CREATE_DOMAIN => {
                    log::trace!("Create domain on core {}", cpuid());
                    let capa =
                        monitor::do_create_domain(vs, domain)
                            .expect("TODO");
                    let mut context = monitor::get_context(*domain, cpuid());
                    context.set(VmcsField::GuestRdi, capa.as_usize(), None)?;
                    context.set(VmcsField::GuestRax, 0, None)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::CONFIGURE => {
                    log::trace!("Configure on core {}", cpuid());
                    let res = if let Ok(bitmap) = Bitmaps::from_usize(arg_1) {
                        let mut value = arg_3 as u64;
                        if bitmap == Bitmaps::CORE {
                            value = platform::remap_core_bitmap(value);
                        }
                        match monitor::do_set_config(
                            vs,
                            domain,
                            LocalCapa::new(arg_2),
                            bitmap,
                            value,
                        ) {
                            Ok(_) => 0,
                            Err(e) => {
                                log::error!("Configuration error: {:?}", e);
                                1
                            }
                        }
                    } else {
                        log::error!("Invalid configuration target");
                        1
                    };
                    monitor::get_context(*domain, cpuid()).set(VmcsField::GuestRax, res, None)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SELF_CONFIG => {
                    log::trace!("Self config on core {}", cpuid());
                    let mut context = monitor::get_context(*domain, cpuid());
                    let field = VmcsField::from_u32(arg_1 as u32).unwrap();
                    if FilteredFields::is_valid_self(field) {
                        context.set(field, arg_2, Some(&mut vs.vcpu)).unwrap();
                        context.set(VmcsField::GuestRax, 0, None).unwrap();
                    } else {
                        context.set(VmcsField::GuestRax, 1, None).unwrap();
                    }
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::ALLOC_CORE_CONTEXT => {
                    log::trace!("Alloc core context on core {}", cpuid());
                    let res = match monitor::do_init_child_context(
                        vs,
                        domain,
                        LocalCapa::new(arg_1),
                        platform::remap_core(arg_2),
                    ) {
                        Ok(_) => 0,
                        Err(e) => {
                            log::error!("Allocating core context error: {:?}", e);
                            1
                        }
                    };
                    monitor::get_context(*domain, cpuid()).set(VmcsField::GuestRax, res, None)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::READ_ALL_GP => {
                    log::trace!("Read all gp register values on core {}", cpuid());
                    monitor::do_get_all_gp(vs, domain, LocalCapa::new(arg_1), platform::remap_core(arg_2))
                        .expect("Problem during copy");
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::WRITE_ALL_GP => {
                    log::trace!("Write all gp register values on core {}", cpuid());
                    monitor::do_set_all_gp(vs, domain, LocalCapa::new(arg_1))
                        .expect("Problem during copy");
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::WRITE_FIELDS => {
                    log::trace!("Write several registers on core {}", cpuid());
                    // Collect the arguments.
                    let values: [(usize, usize); 6] = {
                        let mut context = monitor::get_context(*domain, cpuid());
                        [
                            (
                                context.get(VmcsField::GuestRbp, None).unwrap(),
                                context.get(VmcsField::GuestRbx, None).unwrap(),
                            ),
                            (
                                context.get(VmcsField::GuestRcx, None).unwrap(),
                                context.get(VmcsField::GuestRdx, None).unwrap(),
                            ),
                            (
                                context.get(VmcsField::GuestR8, None).unwrap(),
                                context.get(VmcsField::GuestR9, None).unwrap(),
                            ),
                            (
                                context.get(VmcsField::GuestR10, None).unwrap(),
                                context.get(VmcsField::GuestR11, None).unwrap(),
                            ),
                            (
                                context.get(VmcsField::GuestR12, None).unwrap(),
                                context.get(VmcsField::GuestR13, None).unwrap(),
                            ),
                            (
                                context.get(VmcsField::GuestR14, None).unwrap(),
                                context.get(VmcsField::GuestR15, None).unwrap(),
                            ),
                        ]
                    };
                    let res = match monitor::do_set_fields(
                        vs,
                        domain,
                        LocalCapa::new(arg_1),
                        platform::remap_core(arg_2),
                        &values,
                    ) {
                        Ok(()) => 0,
                        Err(e) => {
                            log::error!("Set fields error {:?}", e);
                            1
                        }
                    };
                    monitor::get_context(*domain, cpuid()).set(VmcsField::GuestRax, res, None)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::CONFIGURE_CORE => {
                    log::trace!("Configure Core on core {}", cpuid());
                    let res = match monitor::do_configure_core(
                        vs,
                        domain,
                        LocalCapa::new(arg_1),
                        platform::remap_core(arg_2),
                        arg_3,
                        arg_4,
                    ) {
                        Ok(()) => 0,
                        Err(e) => {
                            log::error!("Configure core error: {:?}", e);
                            1
                        }
                    };
                    monitor::get_context(*domain, cpuid()).set(VmcsField::GuestRax, res, None)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::GET_CONFIG_CORE => {
                    log::trace!("Get config core on core {}", cpuid());
                    let (rdi, rax) = match monitor::do_get_config_core(
                        vs,
                        domain,
                        LocalCapa::new(arg_1),
                        platform::remap_core(arg_2),
                        arg_3,
                    ) {
                        Ok(v) => (v, 0),
                        Err(e) => {
                            log::error!("Get config core error: {:?}", e);
                            (0, 1)
                        }
                    };
                    let mut context = monitor::get_context(*domain, cpuid());
                    context.set(VmcsField::GuestRax, rax, None)?;
                    context.set(VmcsField::GuestRdi, rdi, None)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SEAL_DOMAIN => {
                    log::trace!("Seal Domain on core {}", cpuid());
                    let capa = monitor::do_seal(vs, domain, LocalCapa::new(arg_1)).expect("TODO");
                    let mut context = monitor::get_context(*domain, cpuid());
                    context.set(VmcsField::GuestRdi, capa.as_usize(), None)?;
                    context.set(VmcsField::GuestRax, 0, None)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SEND => {
                    log::trace!("Send on core {}", cpuid());
                    monitor::do_send(vs, domain, LocalCapa::new(arg_1), LocalCapa::new(arg_2))
                        .expect("TODO");
                    let mut context = monitor::get_context(*domain, cpuid());
                    context.set(VmcsField::GuestRax, 0, None)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SEND_REGION => {
                    log::trace!("Send aliased on core {}", cpuid());
                    // Send a region capa and adds an alias to it.
                    monitor::do_send_region(
                        vs,
                        domain,
                        LocalCapa::new(arg_1),
                        LocalCapa::new(arg_2),
                        arg_3,
                        arg_4 != 0,
                        arg_5,
                        arg_6,
                    )
                    .expect("Failed send aliased");
                    let mut context = monitor::get_context(*domain, cpuid());
                    context.set(VmcsField::GuestRax, 0, None)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SEGMENT_REGION => {
                    log::trace!("Segment region on core {}", cpuid());
                    let (to_send, to_revoke) = match monitor::do_segment_region(
                        vs,
                        domain,
                        LocalCapa::new(arg_1),
                        arg_2 != 0, // is_shared 
                        arg_3,      // start
                        arg_4,      // end
                        arg_5,      // prot
                    ) {
                        Ok((l, r)) => (l,r),
                        Err(e) => {
                            monitor::do_debug(vs, domain);
                            panic!("Error {:?}", e);
                        }
                    };
                    let mut context = monitor::get_context(*domain, cpuid());
                    context.set(VmcsField::GuestRdi, to_send.as_usize(), None)?;
                    context.set(VmcsField::GuestRsi, to_revoke.as_usize(), None)?;
                    context.set(VmcsField::GuestRax, 0, None)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::REVOKE => {
                    log::trace!("Revoke on core {}", cpuid());
                    monitor::do_revoke(vs, domain, LocalCapa::new(arg_1)).expect("TODO");
                    let mut context = monitor::get_context(*domain, cpuid());
                    context.set(VmcsField::GuestRax, 0, None)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::REVOKE_ALIASED_REGION => {
                    log::trace!("Revoke aliased region on core {}", cpuid());
                    monitor::do_revoke_region(vs, domain, LocalCapa::new(arg_1), LocalCapa::new(arg_2), arg_3, arg_4).unwrap();
                    let mut context = monitor::get_context(*domain, cpuid());
                    context.set(VmcsField::GuestRax, 0, None)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::DUPLICATE => {
                    log::trace!("Duplicate");
                    let capa = monitor::do_duplicate(vs, domain, LocalCapa::new(arg_1)).expect("TODO");
                    let mut context = monitor::get_context(*domain, cpuid());
                    context.set(VmcsField::GuestRdi, capa.as_usize(), None)?;
                    context.set(VmcsField::GuestRax, 0, None)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::ENUMERATE => {
                    log::trace!("Enumerate on core {}", cpuid());
                    if let Some((info, next)) =
                        monitor::do_enumerate(vs, domain, NextCapaToken::from_usize(arg_1))
                    {
                        let (v1, v2, v3) = info.serialize();
                        let mut context = monitor::get_context(*domain, cpuid());
                        context.set(VmcsField::GuestRdi, v1, None)?;
                        context.set(VmcsField::GuestRsi, v2, None)?;
                        context.set(VmcsField::GuestRdx, v3 as usize, None)?;
                        context.set(VmcsField::GuestRcx, next.as_usize(), None)?;
                        context.set(VmcsField::GuestRax, 0, None)?;
                    } else {
                        // For now, this marks the end
                        let mut context = monitor::get_context(*domain, cpuid());
                        context.set(VmcsField::GuestRcx, 0, None)?;
                        context.set(VmcsField::GuestRax, 0, None)?;
                    }
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SWITCH => {
                    log::trace!("Switch on core {}", cpuid());
                    {
                        //TODO: figure out a way to fix this.
                        let mut msr = vmx::msr::Msr::new(0xC000_0080);
                        unsafe {
                            msr.write(0xd01);
                        }
                    }
                    vs.vcpu.next_instruction()?;
                    monitor::do_switch(vs, domain, LocalCapa::new(arg_1), cpuid()).expect("TODO");
                    Ok(HandlerResult::Resume)
                }
                calls::DEBUG => {
                    log::trace!("Debug on core {}", cpuid());
                    log::info!("Debug called on {} vcpu: {:x?}", domain.idx(), vs.vcpu);
                    monitor::do_debug(vs, domain);
                    let mut context = monitor::get_context(*domain, cpuid());
                    context.set(VmcsField::GuestRax, 0, None)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::EXIT => {
                    log::info!("MonCall: exit");
                    log::info!("Vcpu: {:x?}", vs.vcpu);
                    Ok(HandlerResult::Exit)
                }
                calls::SERIALIZE_ATTESTATION => {
                    let written = monitor::do_serialize_attestation(vs, domain, arg_1, arg_2).expect("TODO");
                    log::trace!("Wrote {} bytes of attestation", written);
                    let mut context = monitor::get_context(*domain, cpuid());
                    context.set(VmcsField::GuestRdi, written, None)?;
                    context.set(VmcsField::GuestRax, 0, None)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::ENCLAVE_ATTESTATION => {
                    log::trace!("Get attestation!");
                    log::trace!("arg1 {:#x}", arg_1);
                    log::trace!("arg2 {:#x}", arg_2);
                    if let Some(report) = monitor::do_domain_attestation(vs, domain, arg_1, arg_2) {
                        let mut context = monitor::get_context(*domain, cpuid());
                        context.set(VmcsField::GuestRax, 0, None)?;
                        if arg_2 == 0 {
                            context.set(
                                VmcsField::GuestRdi,
                                usize::from_le_bytes(
                                    report.public_key.as_slice()[0..8].try_into().unwrap(),
                                ),
                                None,
                            )?;
                            context.set(
                                VmcsField::GuestRsi,
                                usize::from_le_bytes(
                                    report.public_key.as_slice()[8..16].try_into().unwrap(),
                                ),
                                None,
                            )?;
                            context.set(
                                VmcsField::GuestRdx,
                                usize::from_le_bytes(
                                    report.public_key.as_slice()[16..24].try_into().unwrap(),
                                ),
                                None,
                            )?;
                            context.set(
                                VmcsField::GuestRcx,
                                usize::from_le_bytes(
                                    report.public_key.as_slice()[24..32].try_into().unwrap(),
                                ),
                                None,
                            )?;
                            context.set(
                                VmcsField::GuestR8,
                                usize::from_le_bytes(
                                    report.signed_enclave_data.as_slice()[0..8]
                                        .try_into()
                                        .unwrap(),
                                ),
                                None,
                            )?;
                            context.set(
                                VmcsField::GuestR9,
                                usize::from_le_bytes(
                                    report.signed_enclave_data.as_slice()[8..16]
                                        .try_into()
                                        .unwrap(),
                                ),
                                None,
                            )?;
                        } else if arg_2 == 1 {
                            context.set(
                                VmcsField::GuestRdi,
                                usize::from_le_bytes(
                                    report.signed_enclave_data.as_slice()[16..24]
                                        .try_into()
                                        .unwrap(),
                                ),
                                None,
                            )?;
                            context.set(
                                VmcsField::GuestRsi,
                                usize::from_le_bytes(
                                    report.signed_enclave_data.as_slice()[24..32]
                                        .try_into()
                                        .unwrap(),
                                ),
                                None,
                            )?;
                            context.set(
                                VmcsField::GuestRdx,
                                usize::from_le_bytes(
                                    report.signed_enclave_data.as_slice()[32..40]
                                        .try_into()
                                        .unwrap(),
                                ),
                                None,
                            )?;
                            context.set(
                                VmcsField::GuestRcx,
                                usize::from_le_bytes(
                                    report.signed_enclave_data.as_slice()[40..48]
                                        .try_into()
                                        .unwrap(),
                                ),
                                None,
                            )?;
                            context.set(
                                VmcsField::GuestR8,
                                usize::from_le_bytes(
                                    report.signed_enclave_data.as_slice()[48..56]
                                        .try_into()
                                        .unwrap(),
                                ),
                                None,
                            )?;
                            context.set(
                                VmcsField::GuestR9,
                                usize::from_le_bytes(
                                    report.signed_enclave_data.as_slice()[56..64]
                                        .try_into()
                                        .unwrap(),
                                ),
                                None,
                            )?;
                        }
                    } else {
                        let mut context = monitor::get_context(*domain, cpuid());
                        log::trace!("Attestation error");
                        context.set(VmcsField::GuestRax, 1, None)?;
                    }
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                _ => {
                    log::info!("Unknown MonCall: 0x{:x}", vmcall);
                    log::error!("Exisint on unknown MonCall: {:x?}", vs.vcpu);
                    todo!("Unknown VMCall");
                }
            }
        }
        VmxExitReason::InitSignal /*if domain.idx() == 0*/ => {
            log::trace!("cpu {} received init signal", cpuid());
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::Cpuid if domain.idx() == 0 => {
            let mut context = monitor::get_context(*domain, cpuid());
            let input_eax = context.get(VmcsField::GuestRax, None)?;
            let input_ecx = context.get(VmcsField::GuestRcx, None)?;
            let mut eax: usize;
            let mut ebx: usize;
            let mut ecx: usize;
            let mut edx: usize;

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

            //Apply cpuid filters.
            filter_tpause(input_eax, input_ecx, &mut eax, &mut ebx, &mut ecx, &mut edx);
            filter_mpk(input_eax, input_ecx, &mut eax, &mut ebx, &mut ecx, &mut edx);

            context.set(VmcsField::GuestRax, eax as usize, None)?;
            context.set(VmcsField::GuestRbx, ebx as usize, None)?;
            context.set(VmcsField::GuestRcx, ecx as usize, None)?;
            context.set(VmcsField::GuestRdx, edx as usize, None)?;
            vs.vcpu.next_instruction()?;
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::ControlRegisterAccesses if domain.idx() == 0 => {
            // Handle some of these only for dom0, the other domain's problems
            // are for now forwarded to the manager domain.
            let mut context = monitor::get_context(*domain, cpuid());
            let qualification = vs.vcpu.exit_qualification()?.control_register_accesses();
            match qualification {
                exit_qualification::ControlRegisterAccesses::MovToCr(cr, reg) => {
                    log::info!("MovToCr {:?} into {:?} on domain {:?}", reg, cr, *domain);
                    if !cr.is_guest_cr() {
                        log::error!("Invalid register: {:x?}", cr);
                        panic!("VmExit reason for access to control register is not a control register.");
                    }
                    if cr == VmcsField::GuestCr4 {
                        let value = context.get(reg, Some(&mut vs.vcpu))? as usize;
                        context.set(VmcsField::Cr4ReadShadow, value, Some(&mut vs.vcpu))?;
                        let real_value = value | (1 << 13); // VMXE
                        context.set(cr, real_value, Some(&mut vs.vcpu))?;
                    } else {
                        todo!("Handle cr: {:?}", cr);
                    }

                    vs.vcpu.next_instruction()?;
                }
                _ => todo!("Emulation not yet implemented for {:?}", qualification),
            };
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::EptViolation if domain.idx() == 0 => {
            let addr = vs.vcpu.guest_phys_addr()?;
            log::error!(
                "EPT Violation on dom0! virt: 0x{:x}, phys: 0x{:x}",
                vs.vcpu
                    .guest_linear_addr()
                    .expect("unable to get the virt addr")
                    .as_u64(),
                addr.as_u64(),
            );
            monitor::do_debug(vs, domain);
            panic!("The vcpu {:x?}", vs.vcpu);
        }
        VmxExitReason::Exception if domain.idx() == 0 => {
            panic!("Received an exception on dom0?");
        }
        VmxExitReason::Xsetbv if domain.idx() == 0 => {
            let mut context = monitor::get_context(*domain, cpuid());
            let ecx = context.get(VmcsField::GuestRcx, None)?;
            let eax = context.get(VmcsField::GuestRax, None)?;
            let edx = context.get(VmcsField::GuestRdx, None)?;

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
        VmxExitReason::Wrmsr if domain.idx() == 0 => {
            let mut context = monitor::get_context(*domain, cpuid());
            let ecx = context.get(VmcsField::GuestRcx, None)?;
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
        VmxExitReason::Rdmsr if domain.idx() == 0 => {
            let mut context = monitor::get_context(*domain, cpuid());
            let ecx = context.get(VmcsField::GuestRcx, None)?;
            log::trace!("rdmsr 0x{:x}", ecx);
            if ecx >= 0xc0010000 && ecx <= 0xc0020000 {
                // Reading an AMD specific register, just ignore it
                // The other interval seems to be related to pmu...
                // TODO: figure this out and why it only works on certain hardware.
                vs.vcpu.next_instruction()?;
                log::trace!("rdmsr ignoring amd registers");
                Ok(HandlerResult::Resume)
            } else {
                let msr_reg = vmx::msr::Msr::new(ecx as u32);
                log::trace!("rdmsr: about to read");
                let (low, high) = unsafe { msr_reg.read_raw() };
                log::trace!("Emulated read of msr {:x} = h:{:x};l:{:x}", ecx, high, low);
                context.set(VmcsField::GuestRax, low as usize, None)?;
                context.set(VmcsField::GuestRdx, high as usize, None)?;
                vs.vcpu.next_instruction()?;
                Ok(HandlerResult::Resume)
            }
        }
        // Routing exits to the manager domains.
        VmxExitReason::EptViolation
        | VmxExitReason::ExternalInterrupt
        | VmxExitReason::IoInstruction
        | VmxExitReason::ControlRegisterAccesses
        | VmxExitReason::TripleFault
        | VmxExitReason::Cpuid
        | VmxExitReason::Exception
        | VmxExitReason::Wrmsr
        | VmxExitReason::Rdmsr
        | VmxExitReason::ApicWrite
        | VmxExitReason::InterruptWindow
        | VmxExitReason::Wbinvd
        | VmxExitReason::MovDR
        | VmxExitReason::VirtualizedEoi
        | VmxExitReason::ApicAccess
        | VmxExitReason::VmxPreemptionTimerExpired
        | VmxExitReason::Hlt => {
            log::trace!("Handling {:?} for dom {}", reason, domain.idx());
            if reason == VmxExitReason::ExternalInterrupt {
                /*let address_eoi = 0xfee000b0 as *mut u32;
                unsafe {
                    // Clear the eoi
                    *address_eoi = 0;
                }*/
                x2apic::send_eoi();
            }
            match monitor::do_handle_violation(vs, domain) {
                Ok(_) => {
                    return Ok(HandlerResult::Resume);
                }
                Err(e) => {
                    log::error!("Unable to handle {:?}: {:?}", reason, e);
                    if reason == VmxExitReason::EptViolation {
                        let addr = vs.vcpu.guest_phys_addr()?;
                        log::error!(
                            "Ept Violation! virt: 0x{:x}, phys: 0x{:x} on dom{}",
                            vs.vcpu
                                .guest_linear_addr()
                                .expect("Unable to get virt addr")
                                .as_u64(),
                            addr.as_u64(),
                            *domain
                        );
                    }
                    log::info!("The vcpu: {:x?}", vs.vcpu);
                    return Ok(HandlerResult::Crash);
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
