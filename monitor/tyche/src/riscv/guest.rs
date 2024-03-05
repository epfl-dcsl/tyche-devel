use core::arch::asm;

use capa_engine::{Bitmaps, Domain, Handle, LocalCapa, NextCapaToken};
use riscv_csrs::*;
use riscv_pmp::clear_pmp;
use riscv_sbi::ecall::ecall_handler;
use riscv_sbi::ipi::process_ipi;
use riscv_sbi::sbi::EXT_IPI;
use riscv_utils::{
    aclint_mtimer_set_mtimecmp, clear_mie_mtie, clear_mip_seip, RegisterState, TIMER_EVENT_TICK, NUM_HARTS,
};
use spin::Mutex;

use super::monitor;
use crate::arch::cpuid;
use crate::calls;

const EMPTY_ACTIVE_DOMAIN: Mutex<Option<Handle<Domain>>> = Mutex::new(None);
static ACTIVE_DOMAIN: [Mutex<Option<Handle<Domain>>>; NUM_HARTS] = [EMPTY_ACTIVE_DOMAIN; NUM_HARTS];

// M-mode trap handler
// Saves register state - calls trap_handler - restores register state - mret to intended mode.

#[repr(align(4))]
#[naked]
pub extern "C" fn machine_trap_handler() {
    unsafe {
        asm!(
            "csrrw sp, mscratch, sp
        addi sp, sp, -34*8
        sd ra, 0*8(sp)
        sd a0, 1*8(sp)
        sd a1, 2*8(sp)
        sd a2, 3*8(sp)
        sd a3, 4*8(sp)
        sd a4, 5*8(sp)
        sd a5, 6*8(sp)
        sd a6, 7*8(sp)
        sd a7, 8*8(sp)
        sd t0, 9*8(sp)
        sd t1, 10*8(sp)
        sd t2, 11*8(sp)
        sd t3, 12*8(sp)
        sd t4, 13*8(sp)
        sd t5, 14*8(sp)
        sd t6, 15*8(sp)
        sd zero, 16*8(sp)
        sd gp, 17*8(sp)
        sd tp, 18*8(sp)
        sd s0, 19*8(sp)
        sd s1, 20*8(sp)
        sd s2, 21*8(sp)
        sd s3, 22*8(sp)
        sd s4, 23*8(sp)
        sd s5, 24*8(sp)
        sd s6, 25*8(sp)
        sd s7, 26*8(sp)
        sd s8, 27*8(sp)
        sd s9, 28*8(sp)
        sd s10, 29*8(sp)
        sd s11, 30*8(sp)
        //csrr t1, mepc 
        //sd t1, 31*8(sp)
        //csrr t1, mstatus
        //sd t1, 32*8(sp)
        mv a0, sp      //arg to trap_handler
        auipc x1, 0x0
        addi x1, x1, 10
        j {trap_handler}
        //ld t1, 31*8(sp)
        //csrw mepc, t1
        ld ra, 0*8(sp)
        ld a0, 1*8(sp)
        ld a1, 2*8(sp)
        ld a2, 3*8(sp)
        ld a3, 4*8(sp)
        ld a4, 5*8(sp)
        ld a5, 6*8(sp)
        ld a6, 7*8(sp)
        ld a7, 8*8(sp)
        ld t0, 9*8(sp)
        ld t1, 10*8(sp)
        ld t2, 11*8(sp)
        ld t3, 12*8(sp)
        ld t4, 13*8(sp)
        ld t5, 14*8(sp)
        ld t6, 15*8(sp)
        ld zero, 16*8(sp)
        ld gp, 17*8(sp)
        ld tp, 18*8(sp)
        ld s0, 19*8(sp)
        ld s1, 20*8(sp)
        ld s2, 21*8(sp)
        ld s3, 22*8(sp)
        ld s4, 23*8(sp)
        ld s5, 24*8(sp)
        ld s6, 25*8(sp)
        ld s7, 26*8(sp)
        ld s8, 27*8(sp)
        ld s9, 28*8(sp)
        ld s10, 29*8(sp)
        ld s11, 30*8(sp)
        addi sp, sp, 34*8
        csrrw sp, mscratch, sp
        mret",
            trap_handler = sym handle_exit,
            options(noreturn)
        )
    }
}

pub extern "C" fn exit_handler_failed(mcause: usize) {
    // TODO: Currently, interrupts must be getting redirected here too. Confirm this and then fix
    // it.
    panic!(
        "*******WARNING: Cannot handle this trap with mcause: {:x} !*******",
        mcause
    );
}

// Exit handler - equivalent to x86 handle_exit for its guest.
// In RISC-V, any trap to machine mode will lead to this function being called (via the machine_trap_handler)

pub fn handle_exit(reg_state: &mut RegisterState) {
    let mut ret: isize = 0;
    let mut err: usize = 0;
    let mut out_val: usize = 0;
    let mut mcause: usize;
    let mut mepc: usize;
    let mut mstatus: usize;
    let mut mtval: usize;
    let mut sp: usize = 0;
    let mut mie: usize = 0;
    let mut mip: usize = 0;
    let mut mideleg: usize = 0;
    let mut satp: usize = 0;
    let hartid: usize = cpuid();

    unsafe {
        asm!("csrr {}, mcause", out(reg) mcause);
        asm!("csrr {}, mepc", out(reg) mepc);
        asm!("csrr {}, mstatus", out(reg) mstatus);
        asm!("csrr {}, mtval", out(reg) mtval);
        asm!("csrr {}, mie", out(reg) mie);
        asm!("csrr {}, mideleg", out(reg) mideleg);
        asm!("csrr {}, mip", out(reg) mip);
        asm!("csrr {}, satp", out(reg)satp);
    }

    log::trace!("###### TRAP FROM HART {} ######", hartid);

    log::trace!(
        "mcause {:x}, mepc {:x} mstatus {:x} mtval {:x} mie {:x} mip {:x} mideleg {:x} ra {:x} a0 {:x} a1 {:x} a2 {:x} a3 {:x} a4 {:x} a5 {:x} a6 {:x} a7 {:x} satp: {:x}",
        mcause,
        mepc,
        mstatus,
        mtval,
        mie,
        mip,
        mideleg,
        reg_state.ra,
        reg_state.a0,
        reg_state.a1,
        reg_state.a2,
        reg_state.a3,
        reg_state.a4,
        reg_state.a5,
        reg_state.a6,
        reg_state.a7,
        satp
    );

    // Check which trap it is
    // mcause register holds the cause of the machine mode trap
    match mcause {
        mcause::MSWI => {
            process_ipi(hartid);
        }
        mcause::MTI => {
            clear_mie_mtie();
            log::info!(
                "\nHART {} MTIMER: MEPC: {:x} RA: {:x}\n",
                hartid,
                mepc,
                reg_state.ra
            );
            aclint_mtimer_set_mtimecmp(hartid, TIMER_EVENT_TICK);
        }
        mcause::MEI => {
            panic!("MEI");
        }
        mcause::ILLEGAL_INSTRUCTION => {
            illegal_instruction_handler(mepc, mtval, mstatus, mip, mie);
        }
        mcause::ECALL_FROM_SMODE => {
            if reg_state.a7 == 0x5479636865 {
                //Tyche call
                if reg_state.a0 == 0x5479636865 {
                    log::trace!("Tyche is clearing SIP.SEIE");
                    clear_mip_seip();
                } else {
                    misaligned_load_handler(reg_state);
                }
            } else {
                ecall_handler(&mut ret, &mut err, &mut out_val, *reg_state);
                reg_state.a0 = ret;
                reg_state.a1 = out_val as isize;
            }
        }
        mcause::LOAD_ADDRESS_MISALIGNED => {
            panic!("Load address misaligned.");
        }
        mcause::STORE_ACCESS_FAULT
        | mcause::LOAD_ACCESS_FAULT
        | mcause::INSTRUCTION_ACCESS_FAULT => {
            panic!(
                "PMP Access Fault! mcause: {:x} mepc: {:x} mtval: {:x} satp: {:x} mstatus: {:x}",
                mcause, mepc, mtval, satp, mstatus
            );
        }
        mcause::INSTRUCTION_PAGE_FAULT | mcause::LOAD_PAGE_FAULT | mcause::STORE_PAGE_FAULT => {
            panic!("Page Fault!");
        }
        _ => exit_handler_failed(mcause),
        //Default - just print whatever information you can about the trap.
    }

    log::trace!("Returning from Trap on Hart {}", hartid);
    // Return to the next instruction after the trap.
    // i.e. mepc += 4
    // TODO: This shouldn't happen in case of switch.
    if (mcause & (1 << 63)) != (1 << 63) {
        unsafe {
            asm!("csrr t0, mepc");
            asm!("addi t0, t0, 0x4");
            asm!("csrw mepc, t0");
        }
    }
}

pub fn illegal_instruction_handler(
    mepc: usize,
    mtval: usize,
    mstatus: usize,
    mip: usize,
    mie: usize,
) {
    panic!(
        "Illegal Instruction Trap! mepc: {:x} mtval: {:x} mstatus: {:x} mip: {:x} mie: {:x}",
        mepc, mtval, mstatus, mip, mie
    );
}

pub fn misaligned_load_handler(reg_state: &mut RegisterState) {
    if reg_state.a7 == 0x5479636865 {
        //It's a Tyche Call
        let tyche_call: usize = reg_state.a0.try_into().unwrap();
        let arg_1: usize = reg_state.a1.try_into().unwrap();
        let arg_2: usize = reg_state.a2;
        let arg_3: usize = reg_state.a3;
        let arg_4: usize = reg_state.a4;
        let arg_5: usize = reg_state.a5;
        let arg_6: usize = reg_state.a6;

        let mut active_dom: Handle<Domain>;
        let hartid = cpuid();
        unsafe {
            active_dom = get_active_dom(hartid);
        }

        match tyche_call {
            calls::CREATE_DOMAIN => {
                log::debug!("Create Domain");
                let capa = monitor::do_create_domain(active_dom).expect("TODO");
                reg_state.a0 = 0x0;
                reg_state.a1 = capa.as_usize() as isize;
                //TODO: Ok(HandlerResult::Resume) There is no main loop to check what happened
                //here, do we need a wrapper to determine when we crash? For all cases except Exit,
                //not yet. Must be handled after addition of more exception handling in Tyche.
            }
            calls::CONFIGURE => {
                log::debug!("Configure");
                if let Ok(bitmap) = Bitmaps::from_usize(arg_1) {
                    match monitor::do_set_config(
                        active_dom,
                        LocalCapa::new(arg_2),
                        bitmap,
                        arg_3 as u64,
                    ) {
                        Ok(_) => {
                            reg_state.a0 = 0x0;
                        }
                        Err(e) => {
                            log::error!("Configuration error: {:?}", e);
                            reg_state.a0 = 0x1;
                        }
                    }
                } else {
                    log::error!("Invalid configuration target");
                    reg_state.a0 = 0x1;
                }
            }
            calls::SET_ENTRY_ON_CORE => {
                log::debug!("Set entry on core {}", arg_2);
                match monitor::do_set_entry(
                    active_dom,
                    LocalCapa::new(arg_1),
                    arg_2,
                    arg_3,
                    arg_4,
                    arg_5,
                ) {
                    Ok(()) => reg_state.a0 = 0x0,
                    Err(e) => {
                        log::error!("Unable to set entry: {:?}", e);
                        reg_state.a0 = 0x1;
                    }
                }
            }
            calls::SEAL_DOMAIN => {
                log::debug!("Seal Domain");
                let capa = monitor::do_seal(active_dom, LocalCapa::new(arg_1)).expect("TODO");
                reg_state.a0 = 0x0;
                reg_state.a1 = capa.as_usize() as isize;
            }
            calls::SHARE => {
                log::debug!("Share");
                //let capa = monitor::.do_().expect("TODO");
                reg_state.a0 = 0x0;
                reg_state.a1 = 0x0;
            }
            calls::SEND => {
                log::debug!("Send");
                monitor::do_send(active_dom, LocalCapa::new(arg_1), LocalCapa::new(arg_2))
                    .expect("TODO");
                reg_state.a0 = 0x0;
            }
            calls::SEGMENT_REGION => {
                log::debug!("Segment Region");
                let (left, right) = monitor::do_segment_region(
                    active_dom,
                    LocalCapa::new(arg_1),
                    arg_2,
                    arg_3,
                    arg_6 >> 32,
                    arg_4,
                    arg_5,
                    (arg_6 << 32) >> 32,
                )
                .expect("TODO");
                reg_state.a0 = 0x0;
                reg_state.a1 = left.as_usize() as isize;
                reg_state.a2 = right.as_usize();
            }
            calls::REVOKE => {
                log::debug!("Revoke");
                monitor::do_revoke(active_dom, LocalCapa::new(arg_1)).expect("TODO");
                reg_state.a0 = 0x0;
            }
            calls::DUPLICATE => {
                log::debug!("Duplicate");
                let capa = monitor::do_duplicate(active_dom, LocalCapa::new(arg_1)).expect("TODO");
                reg_state.a0 = 0x0;
                reg_state.a1 = capa.as_usize() as isize;
            }
            calls::ENUMERATE => {
                log::debug!("Enumerate");
                if let Some((info, next)) =
                    monitor::do_enumerate(active_dom, NextCapaToken::from_usize(arg_1))
                {
                    let (v1, v2, v3) = info.serialize();
                    reg_state.a1 = v1 as isize;
                    reg_state.a2 = v2 as usize;
                    reg_state.a3 = v3 as usize;
                    reg_state.a4 = next.as_usize();
                } else {
                    // For now, this marks the end
                    reg_state.a4 = 0;
                }
                reg_state.a0 = 0x0;
            }
            calls::SWITCH => {
                log::debug!("Switch");
                monitor::do_switch(active_dom, LocalCapa::new(arg_1), hartid, reg_state)
                    .expect("TODO");
            }
            calls::ENCLAVE_ATTESTATION => {
                log::trace!("Get attestation!");
                if let Some(report) = monitor::do_domain_attestation(active_dom, arg_1, arg_2) {
                    reg_state.a0 = 0;
                    if arg_2 == 0 {
                        reg_state.a1 = usize::from_le_bytes(
                            report.public_key.as_slice()[0..8].try_into().unwrap(),
                        ) as isize;
                        reg_state.a2 = usize::from_le_bytes(
                            report.public_key.as_slice()[8..16].try_into().unwrap(),
                        );
                        reg_state.a3 = usize::from_le_bytes(
                            report.public_key.as_slice()[16..24].try_into().unwrap(),
                        ) as usize;
                        reg_state.a4 = usize::from_le_bytes(
                            report.public_key.as_slice()[24..32].try_into().unwrap(),
                        ) as usize;
                        reg_state.a5 = usize::from_le_bytes(
                            report.signed_enclave_data.as_slice()[0..8]
                                .try_into()
                                .unwrap(),
                        ) as usize;
                        reg_state.a6 = usize::from_le_bytes(
                            report.signed_enclave_data.as_slice()[8..16]
                                .try_into()
                                .unwrap(),
                        ) as usize;
                    } else if arg_2 == 1 {
                        reg_state.a1 = usize::from_le_bytes(
                            report.signed_enclave_data.as_slice()[16..24]
                                .try_into()
                                .unwrap(),
                        ) as isize;
                        reg_state.a2 = usize::from_le_bytes(
                            report.signed_enclave_data.as_slice()[24..32]
                                .try_into()
                                .unwrap(),
                        );
                        reg_state.a3 = usize::from_le_bytes(
                            report.signed_enclave_data.as_slice()[32..40]
                                .try_into()
                                .unwrap(),
                        );
                        reg_state.a4 = usize::from_le_bytes(
                            report.signed_enclave_data.as_slice()[40..48]
                                .try_into()
                                .unwrap(),
                        );
                        reg_state.a5 = usize::from_le_bytes(
                            report.signed_enclave_data.as_slice()[48..56]
                                .try_into()
                                .unwrap(),
                        );
                        reg_state.a6 = usize::from_le_bytes(
                            report.signed_enclave_data.as_slice()[56..64]
                                .try_into()
                                .unwrap(),
                        );
                    }
                } else {
                    log::trace!("Attestation error");
                    reg_state.a0 = 1;
                }
            }
            calls::DEBUG => {
                log::debug!("Debug");
                //monitor::do_debug();
                reg_state.a0 = 0x0;
            }
            calls::EXIT => {
                log::debug!("Tyche Call: Exit");
                //TODO
                //let capa = monitor::.do_().expect("TODO");
                reg_state.a0 = 0x0;
            }
            _ => {
                /*TODO: Invalid Tyche Call*/
                log::debug!("Invalid Tyche Call: {:x}", reg_state.a0);
                todo!("Unknown Tyche Call.");
            }
        }
        monitor::apply_core_updates(&mut active_dom, hartid, reg_state);
        //Updating the state
        unsafe {
            set_active_dom(hartid, active_dom);
        }
    }
    //TODO: ELSE NOT TYCHE CALL
    //Handle Illegal Instruction Trap
}

pub unsafe fn get_active_dom(hartid: usize) -> (Handle<Domain>) {
    return ACTIVE_DOMAIN[hartid].lock().unwrap();
}

pub unsafe fn set_active_dom(hartid: usize, domain: Handle<Domain>) {
    let mut active_domain = ACTIVE_DOMAIN[hartid].lock(); 
    *active_domain = Some(domain);
}
