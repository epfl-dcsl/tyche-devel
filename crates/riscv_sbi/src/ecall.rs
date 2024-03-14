use core::arch::asm;
use core::sync::atomic::Ordering;

use capa_engine::Buffer;
use riscv_utils::{
    RegisterState, AVAILABLE_HART_MASK, HART_IPI_SYNC, HART_START, HART_START_ADDR,
    HART_START_ARG1, IPI_TYPE_SMODE, IPI_TYPE_TLB, NUM_HARTS, NUM_HARTS_AVAILABLE,
};
use spin::Mutex;

use crate::ipi::{aclint_mswi_send_ipi, ipi_handling_failed, process_tlb_ipi};
use crate::rfence::local_sfence_vma_asid;
use crate::{
    sbi, sbi_ext_base, sbi_ext_hsm, sbi_ext_ipi, sbi_ext_rfence, IPIRequest, ECALL_IMPID,
    ECALL_VERSION_MAJOR, ECALL_VERSION_MINOR, SPEC_VERSION_MAJOR_MASK, SPEC_VERSION_MAJOR_OFFSET,
    TYCHE_SBI_VERSION,
};

pub static HART_IPI_BUFFER: [Mutex<Buffer<IPIRequest>>; NUM_HARTS] = [EMPTY_IPI_BUFFER; NUM_HARTS];

const EMPTY_IPI_BUFFER: Mutex<Buffer<IPIRequest>> = Mutex::new(Buffer::new());

pub fn ecall_handler(
    mut ret: &mut isize,
    mut err: &mut usize,
    mut out_val: &mut usize,
    reg_state: RegisterState,
) {
    //println!("ecall handler a7: {:x}",a7);
    match reg_state.a7 {
        sbi::EXT_BASE => sbi_ext_base_handler(
            &mut ret,
            &mut err,
            &mut out_val,
            reg_state.a0.try_into().unwrap(),
            reg_state.a6,
        ),
        sbi::EXT_HSM => sbi_ext_hsm_handler(
            &mut ret,
            &mut err,
            &mut out_val,
            reg_state.a0.try_into().unwrap(),
            reg_state.a1.try_into().unwrap(),
            reg_state.a2,
            reg_state.a6,
        ),
        sbi::EXT_IPI => sbi_ext_ipi_handler(
            &mut ret,
            &mut err,
            &mut out_val,
            reg_state.a0.try_into().unwrap(),
            reg_state.a1,
            reg_state.a6,
        ),
        sbi::EXT_RFENCE => sbi_ext_rfence_handler(
            &mut ret,
            &mut err,
            &mut out_val,
            reg_state.a0.try_into().unwrap(),
            reg_state.a1,
            reg_state.a2,
            reg_state.a3,
            reg_state.a4,
            reg_state.a6,
        ),
        _ => ecall_handler_failed(reg_state.a7, reg_state.a6),
    }
}

// ------------------------------- SBI BASE CALL HANDLER and HELPERS ----------------------- //
pub fn sbi_ext_base_handler(
    ret: &mut isize,
    _err: &mut usize,
    out_val: &mut usize,
    a0: usize,
    a6: usize,
) {
    //let mut a6: usize;
    //unsafe { asm!("mv {}, a6", out(reg) a6); }
    //println!("base_handler a6: {:x}",a6);
    *ret = 0;
    match a6 {
        sbi_ext_base::GET_SPEC_VERSION => *out_val = get_sbi_spec_version(),
        sbi_ext_base::GET_IMP_ID => *out_val = ECALL_IMPID,
        sbi_ext_base::GET_IMP_VERSION => *out_val = TYCHE_SBI_VERSION,
        sbi_ext_base::GET_MVENDORID | sbi_ext_base::GET_MARCHID | sbi_ext_base::GET_MIMPID => {
            *out_val = get_m_x_id(a6)
        }
        sbi_ext_base::PROBE_EXT => (*ret, *out_val) = probe(a0, a6),
        _ => ecall_handler_failed(sbi::EXT_BASE, a6),
    }
}

pub fn sbi_ext_hsm_handler(
    _ret: &mut isize,
    _err: &mut usize,
    _out_val: &mut usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a6: usize,
) {
    //Todo: Need to support various HSM extension calls - for now just processing hart start
    if a0 > 3 {
        log::info!("Invalid hart id!");
        return;
    }

    match a6 {
        sbi_ext_hsm::HART_START => {
            log::info!("SBI_HSM_HART_START!");
            //unsafe { asm!("csrsi mip, 2"); }
            //a0: hartid, a1: start_addr, a2: arg1
            HART_START_ADDR[a0].store(a1, Ordering::SeqCst);
            HART_START_ARG1[a0].store(a2, Ordering::SeqCst);
            HART_START[a0].store(true, Ordering::SeqCst);
            aclint_mswi_send_ipi(a0);
        }
        _ => ecall_handler_failed(sbi::EXT_HSM, a6),
    }
}

pub fn sbi_ext_ipi_handler(
    _ret: &mut isize,
    _err: &mut usize,
    _out_val: &mut usize,
    a0: usize,
    a1: isize,
    a6: usize,
) {
    //a0: hart_mask, a1: hart_mask_base
    //Todo for later: The SBI spec states the following: "If a lower privilege mode needs to pass
    //information about more than xlen harts, it should invoke multiple instances of the SBI
    //function call". This is unspecified in terms of how the multiple instances should behave and
    //how the SEE should know that it's a continuation of the previous call. I am ignoring this
    //case for the time being.

    //Todo: The implementation doesn't check for HART STATE at this point. Need to add metadata in
    //Tyche to track this.

    let src_hartid: usize;
    unsafe {
        asm!("csrr {}, mhartid", out(reg) src_hartid);
    }
    let number_of_harts = NUM_HARTS_AVAILABLE.load(Ordering::SeqCst);

    if a6 == sbi_ext_ipi::SEND_IPI {
        //impl : sbi_ipi_send_many()
        //hart_mask_base = -1 => all available harts.
        if a1 == -1 {
            //Send IPI to all available harts.
            for i in 0..number_of_harts {
                if i != src_hartid {
                    //log::info!("All harts: Sending IPI to hart {}", i);
                    //let mut ipi_requests = HART_IPI_BUFFER[i as usize].lock();
                    //ipi_requests.push(IPIRequest::SMode);
                    //drop(ipi_requests);
                    IPI_TYPE_SMODE[i].store(true, Ordering::SeqCst);
                    aclint_mswi_send_ipi(i);
                }
            }
        } else {
            //Check hmask starting from hbase hartid.
            let mut available_hart_mask: usize;
            available_hart_mask = AVAILABLE_HART_MASK.load(Ordering::SeqCst) >> a1;
            let mut target_hart_mask: usize = a0;
            for i in a1.try_into().unwrap()..number_of_harts {
                if (((available_hart_mask & 0x1) & (target_hart_mask & 1)) == 1)
                    && (i != src_hartid)
                {
                    //TODO: WHAT ABOUT CURRENT HART? No such check in OpenSBI - let's see if it's
                    //needed.
                    //log::info!("Hmask harts: Sending IPI to hart {} a0: {}, a1: {}", i, a0, a1);
                    //let mut ipi_requests = HART_IPI_BUFFER[i as usize].lock();
                    //ipi_requests.push(IPIRequest::SMode);
                    //drop(ipi_requests);
                    IPI_TYPE_SMODE[i].store(true, Ordering::SeqCst);
                    aclint_mswi_send_ipi(i);
                }
                available_hart_mask >>= 1;
                target_hart_mask >>= 1;
            }
        }
        //TODO: RC check once dealing with TLB IPIs.
        //URGENT TODO 2 : SYNC
    }
}

pub fn sbi_ext_rfence_handler(
    _ret: &mut isize,
    _err: &mut usize,
    _out_val: &mut usize,
    a0: usize,
    a1: isize,
    start: usize,
    size: usize,
    asid: usize,
    a6: usize,
) {
    //a0: hart_mask, a1: hart_mask_base, a2: start, a3: size, a4: asid

    let src_hartid: usize;
    unsafe {
        asm!("csrr {}, mhartid", out(reg) src_hartid);
    }
    let number_of_harts = NUM_HARTS_AVAILABLE.load(Ordering::SeqCst);

    match a6 {
        sbi_ext_rfence::REMOTE_SFENCE_VMA_ASID => {
            if a1 == -1 {
                //Send IPI to all available harts.
                for i in 0..number_of_harts {
                    if i == src_hartid {
                        local_sfence_vma_asid(start, size, asid);
                    } else {
                        //Push req into buffer
                        //log::info!("All: Sending IPI to hart {} from hart {}", src_hartid, i);
                        let mut ipi_requests = HART_IPI_BUFFER[i as usize].lock();
                        ipi_requests
                            .push(IPIRequest::RfenceSfenceVMAASID {
                                src_hartid,
                                start,
                                size,
                                asid,
                            })
                            .unwrap();
                        drop(ipi_requests);
                        //Send IPI to the hart.
                        HART_IPI_SYNC[src_hartid].fetch_add(1, Ordering::SeqCst);
                        IPI_TYPE_TLB[i].store(true, Ordering::SeqCst);
                        aclint_mswi_send_ipi(i);

                        //HART_IPI_SYNC[src_hartid].fetch_add(1, Ordering::SeqCst);
                    }
                }
            } else {
                //Check hmask starting from hbase hartid.
                let mut available_hart_mask: usize;
                available_hart_mask = AVAILABLE_HART_MASK.load(Ordering::SeqCst) >> a1;
                //Currently assuming all harts are available to send IPIs.
                let mut target_hart_mask: usize = a0;
                for i in a1.try_into().unwrap()..number_of_harts {
                    if ((available_hart_mask & 0x1) & (target_hart_mask & 1)) == 1 {
                        if i == src_hartid {
                            local_sfence_vma_asid(start, size, asid);
                        } else {
                            //Push req into buffer
                            //log::info!("Hmask: Sending IPI to hart {} from hart {}", src_hartid, i);
                            let mut ipi_requests = HART_IPI_BUFFER[i as usize].lock();
                            ipi_requests
                                .push(IPIRequest::RfenceSfenceVMAASID {
                                    src_hartid,
                                    start,
                                    size,
                                    asid,
                                })
                                .unwrap();
                            drop(ipi_requests);
                            //Send IPI to the hart.
                            HART_IPI_SYNC[src_hartid].fetch_add(1, Ordering::SeqCst);
                            //log::info!("Sending IPI to hart {} from hart {}", src_hartid, i);
                            IPI_TYPE_TLB[i].store(true, Ordering::SeqCst);
                            aclint_mswi_send_ipi(i);
                            //HART_IPI_SYNC[src_hartid].fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    available_hart_mask >>= 1;
                    target_hart_mask >>= 1;
                }
            }
        }
        //sbi_ext_rfence::REMOTE_FENCE_I => ecall_handler_failed(),
        //sbi_ext_rfence::REMOTE_SFENCE_VMA => panic!("Cannot handle SFENCE.VMA"),
        _ => ecall_handler_failed(sbi::EXT_RFENCE, a6),
    }

    //SYNC:

    while HART_IPI_SYNC[src_hartid].load(Ordering::SeqCst) > 0 {
        //Try to process local hart ipis instead of defaulting to busy wait so as to prevent deadlocks, or else just spin loop
        //log::info!("Waiting in hart {}",src_hartid);
        //process_ipi(src_hartid);
        //core::hint::spin_loop();
        let mut ipi_requests = HART_IPI_BUFFER[src_hartid].lock();
        if let Some(ipi_req) = ipi_requests.pop() {
            match ipi_req {
                IPIRequest::RfenceSfenceVMAASID {
                    src_hartid,
                    start,
                    size,
                    asid,
                } => {
                    process_tlb_ipi(src_hartid, start, size, asid);
                }
                _ => ipi_handling_failed(),
            }
        }
        drop(ipi_requests);
    }
    //log::info!("Done waiting in hart {}",src_hartid);
}

pub fn get_sbi_spec_version() -> usize {
    let mut spec_ver: usize;

    spec_ver = (ECALL_VERSION_MAJOR << SPEC_VERSION_MAJOR_OFFSET)
        & (SPEC_VERSION_MAJOR_MASK << SPEC_VERSION_MAJOR_OFFSET);
    spec_ver |= ECALL_VERSION_MINOR;
    //println!("Computed spec_version: {:x}",spec_ver);
    return spec_ver;
}

pub fn probe(a0: usize, a6: usize) -> (isize, usize) {
    //println!("probing a0 {:x}",a0);
    let mut ret: isize = 0;
    let mut out_val: usize = 0;

    match a0 {
        sbi::EXT_HSM => {
            match a6 {
                sbi_ext_hsm::HART_SUSPEND => {
                    log::info!("Hart_suspend");
                    ret = 0;
                    out_val = 1;
                    //sbi_hsm_hart_suspend();
                }
                sbi_ext_hsm::HART_START | sbi_ext_hsm::HART_STOP | sbi_ext_hsm::HART_GET_STATUS => {
                    log::info!("Hart start/stop/status");
                    ret = 0;
                    out_val = 0;
                }
                _ => ecall_handler_failed(sbi::EXT_BASE, a0),
            }
        }
        sbi::EXT_TIME | sbi::EXT_IPI | sbi::EXT_RFENCE => {
            ret = 0;
            out_val = 1;
            log::info!("PROBING sbi::EXT_TIME/IPI/RFENCE.")
        }
        //Handlers for the corresponding ecall are not yet implemented.
        //sbi::EXT_RFENCE => {
        //    ret = 1;
        //    log::info!("PROBING sbi::EXT_RFENCE")
        //}
        sbi::EXT_SRST => out_val = sbi_ext_srst_probe(a0),
        _ => ecall_handler_failed(sbi::EXT_BASE, a0),
    }

    //println!("Returning from probe {}",ret);

    return (ret, out_val);
}

/* pub fn sbi_hsm_hart_suspend() -> usize {
    //let mut ret: usize = 0;
    //let mut oldstate: usize = 0;

    //let hart_scratch: &mut sbi_scratch = read_mscratch();



    //Todo: Sanity check on domain assigned to current hart - suspends are only allowed from U-mode/S-mode.
    //Currently, we don't track "domain" as used in openSBI in Tyche. (See openSBI boot log domain
    //info). This is orthogonal to Tyche's "domains".

    //Todo: Sanity check on suspend type
    //---

        //Todo: More sanity checks - non-retentive suspend
        //

    //Todo: Save next_addr, next_mode, priv

    //sbi_scratch offset ptr - scratch is nothing but mscratch register value - which typically
    //should point to the scratch memory of that hart.

} */

pub fn get_m_x_id(a6: usize) -> usize {
    let mut ret: usize = 0;
    match a6 {
        sbi_ext_base::GET_MVENDORID => unsafe {
            asm!("csrr {}, mvendorid", out(reg) ret);
        },
        sbi_ext_base::GET_MARCHID => unsafe {
            asm!("csrr {}, marchid", out(reg) ret);
        },
        sbi_ext_base::GET_MIMPID => unsafe {
            asm!("csrr {}, mimpid", out(reg) ret);
        },
        _ => log::info!("Invalid get_m_x_id request!"),
    }
    //println!("Returning m_x_id {:x}",ret);
    return ret;
}

pub fn sbi_ext_srst_probe(_a0: usize) -> usize {
    //TODO For now this function pretends that srst extension probe works as expected.
    //If needed in the future, this must be implemented fully - refer to openSBI for this.
    return 1;
}

pub fn ecall_handler_failed(a7: usize, a6: usize) {
    log::trace!("SBI ecall not supported: a7 {:x} a6 {:x}.", a7, a6);
}
