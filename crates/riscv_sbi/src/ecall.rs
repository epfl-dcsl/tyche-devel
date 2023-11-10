use core::arch::asm;
use core::sync::atomic::Ordering;

use capa_engine::Buffer;
use qemu::println;
use riscv_serial::write_char;
use riscv_utils::{
    aclint_mtimer_set_mtimecmp, clear_mip_stip, RegisterState, AVAILABLE_HART_MASK, HART_IPI_SYNC,
    HART_START, HART_START_ADDR, HART_START_ARG1, IPI_TYPE_SMODE, IPI_TYPE_TLB, NUM_HARTS,
    NUM_HARTS_AVAILABLE,
};
use spin::Mutex;

use crate::ipi::{aclint_mswi_send_ipi, ipi_handling_failed, process_ifence_ipi, process_tlb_ipi};
use crate::rfence::{local_ifence, local_sfence_vma_asid};
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
            0, // Neelu: start and size are 0 for now, sfence.vma even for asid.
            0,
            reg_state.a4,
            reg_state.a6,
        ),
        sbi::EXT_TIME => {
            let hartid: usize;
            unsafe {
                asm!("csrr {}, mhartid", out(reg) hartid);
            }
            clear_mip_stip();
            aclint_mtimer_set_mtimecmp(hartid, reg_state.a0.try_into().unwrap());
            // setting mie.mtie is already taken care of during set_mtimecmp.
        }
        sbi::EXT_PUTCHAR_LEGACY => write_char(reg_state.a0 as u8 as char),
        _ => ecall_handler_failed(reg_state.a7, reg_state.a6),
    }
}

//  ------------------------------- SBI BASE CALL HANDLER and HELPERS ----------------------- //
pub fn sbi_ext_base_handler(
    ret: &mut isize,
    _err: &mut usize,
    out_val: &mut usize,
    a0: usize,
    a6: usize,
) {
    *ret = 0;
    match a6 {
        sbi_ext_base::GET_SPEC_VERSION => *out_val = get_sbi_spec_version(),
        sbi_ext_base::GET_IMP_ID => *out_val = ECALL_IMPID,
        sbi_ext_base::GET_IMP_VERSION => *out_val = TYCHE_SBI_VERSION,
        sbi_ext_base::GET_MVENDORID | sbi_ext_base::GET_MARCHID | sbi_ext_base::GET_MIMPID => {
            *out_val = get_m_x_id(a6)
        }
        sbi_ext_base::PROBE_EXT => (*ret, *out_val) = probe(a0, a6),
        sbi_ext_base::PMU_EXT => (), // Do nothing.
        _ => ecall_handler_failed(sbi::EXT_BASE, a6),
    }
    println!("[TYCHE] SBI_base_handler complete");
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
    // Todo: Need to support various HSM extension calls - for now just processing hart start
    if a0 > 3 {
        println!("Invalid hart id!");
        return;
    }

    match a6 {
        sbi_ext_hsm::HART_START => {
            println!("SBI_HSM_HART_START!");
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
    // a0: hart_mask, a1: hart_mask_base
    // Todo for later: The SBI spec states the following: "If a lower privilege mode needs to pass
    // information about more than xlen harts, it should invoke multiple instances of the SBI
    // function call". This is unspecified in terms of how the multiple instances should behave and
    // how the SEE should know that it's a continuation of the previous call. I am ignoring this
    // case for the time being.

    // Todo: The implementation doesn't check for HART STATE at this point.
    // Need to add metadata in Tyche to track this.

    let src_hartid: usize;
    unsafe {
        asm!("csrr {}, mhartid", out(reg) src_hartid);
    }
    let number_of_harts = NUM_HARTS_AVAILABLE.load(Ordering::SeqCst);

    if a6 == sbi_ext_ipi::SEND_IPI {
        // impl : sbi_ipi_send_many()
        // hart_mask_base = -1 => all available harts.
        if a1 == -1 {
            // Send IPI to all available harts.
            for i in 0..number_of_harts {
                if i != src_hartid {
                    // log::info!("All harts: Sending IPI to hart {}", i);
                    // let mut ipi_requests = HART_IPI_BUFFER[i as usize].lock();
                    // ipi_requests.push(IPIRequest::SMode);
                    // drop(ipi_requests);
                    IPI_TYPE_SMODE[i].store(true, Ordering::SeqCst);
                    aclint_mswi_send_ipi(i);
                }
            }
        } else {
            // Check hmask starting from hbase hartid.
            let mut available_hart_mask: usize;
            available_hart_mask = AVAILABLE_HART_MASK.load(Ordering::SeqCst) >> a1;
            let mut target_hart_mask: usize = a0;
            for i in a1.try_into().unwrap()..number_of_harts {
                if (((available_hart_mask & 0x1) & (target_hart_mask & 1)) == 1)
                    && (i != src_hartid)
                {
                    // TODO: WHAT ABOUT CURRENT HART? No such check in OpenSBI - let's see if it's
                    // needed.
                    // log::info!("Hmask harts: Sending IPI from hart {} to hart {} a0: {}, a1: {}", src_hartid, i, a0, a1);
                    // let mut ipi_requests = HART_IPI_BUFFER[i as usize].lock();
                    // ipi_requests.push(IPIRequest::SMode);
                    // drop(ipi_requests);
                    IPI_TYPE_SMODE[i].store(true, Ordering::SeqCst);
                    aclint_mswi_send_ipi(i);
                }
                available_hart_mask >>= 1;
                target_hart_mask >>= 1;
            }
        }
        // TODO: RC check once dealing with TLB IPIs.
        // URGENT TODO 2 : SYNC
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
    // a0: hart_mask, a1: hart_mask_base, a2: start, a3: size, a4: asid

    // println!("[TYCHE] Rfence service call");

    let src_hartid: usize;
    unsafe {
        asm!("csrr {}, mhartid", out(reg) src_hartid);
    }
    let number_of_harts = NUM_HARTS_AVAILABLE.load(Ordering::SeqCst);
    // println!("[TYCHE] START Rfence service call on Src Hart {}", src_hartid);
    match a6 {
        sbi_ext_rfence::REMOTE_SFENCE_VMA_ASID | sbi_ext_rfence::REMOTE_SFENCE_VMA => {
            if a1 == -1 {
                // Send IPI to all available harts.
                for i in 0..number_of_harts {
                    if i == src_hartid {
                        local_sfence_vma_asid(start, size, asid);
                    } else {
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
                        // Send IPI to the hart.
                        HART_IPI_SYNC[src_hartid].fetch_add(1, Ordering::SeqCst);
                        IPI_TYPE_TLB[i].store(true, Ordering::SeqCst);
                        aclint_mswi_send_ipi(i);
                    }
                }
            } else {
                // Check hmask starting from hbase hartid.
                let mut available_hart_mask: usize;
                available_hart_mask = AVAILABLE_HART_MASK.load(Ordering::SeqCst) >> a1;
                // Currently assuming all harts are available to send IPIs.
                let mut target_hart_mask: usize = a0;
                for i in a1.try_into().unwrap()..number_of_harts {
                    if ((available_hart_mask & 0x1) & (target_hart_mask & 1)) == 1 {
                        if i == src_hartid {
                            local_sfence_vma_asid(start, size, asid);
                        } else {
                            // Push req into buffer
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
                            // Send IPI to the hart.
                            HART_IPI_SYNC[src_hartid].fetch_add(1, Ordering::SeqCst);
                            IPI_TYPE_TLB[i].store(true, Ordering::SeqCst);
                            aclint_mswi_send_ipi(i);
                        }
                    }
                    available_hart_mask >>= 1;
                    target_hart_mask >>= 1;
                }
            }
        }
        sbi_ext_rfence::REMOTE_FENCE_I => {
            if a1 == -1 {
                // Send IPI to all available harts.
                for i in 0..number_of_harts {
                    if i == src_hartid {
                        local_ifence();
                    } else {
                        // Push req into buffer
                        let mut ipi_requests = HART_IPI_BUFFER[i as usize].lock();
                        ipi_requests
                            .push(IPIRequest::RfenceIfence { src_hartid })
                            .unwrap();
                        drop(ipi_requests);
                        // Send IPI to the hart.
                        HART_IPI_SYNC[src_hartid].fetch_add(1, Ordering::SeqCst);
                        IPI_TYPE_TLB[i].store(true, Ordering::SeqCst);
                        aclint_mswi_send_ipi(i);
                    }
                }
            } else {
                // Check hmask starting from hbase hartid.
                let mut available_hart_mask: usize;
                available_hart_mask = AVAILABLE_HART_MASK.load(Ordering::SeqCst) >> a1;
                // Currently assuming all harts are available to send IPIs.
                let mut target_hart_mask: usize = a0;
                for i in a1.try_into().unwrap()..number_of_harts {
                    if ((available_hart_mask & 0x1) & (target_hart_mask & 1)) == 1 {
                        if i == src_hartid {
                            local_ifence();
                        } else {
                            // Push req into buffer
                            let mut ipi_requests = HART_IPI_BUFFER[i as usize].lock();
                            ipi_requests
                                .push(IPIRequest::RfenceIfence { src_hartid })
                                .unwrap();
                            drop(ipi_requests);
                            // Send IPI to the hart.
                            HART_IPI_SYNC[src_hartid].fetch_add(1, Ordering::SeqCst);
                            IPI_TYPE_TLB[i].store(true, Ordering::SeqCst);
                            aclint_mswi_send_ipi(i);
                        }
                    }
                    available_hart_mask >>= 1;
                    target_hart_mask >>= 1;
                }
            }
        }
        _ => ecall_handler_failed(sbi::EXT_RFENCE, a6),
    }

    // SYNC:

    while HART_IPI_SYNC[src_hartid].load(Ordering::SeqCst) > 0 {
        // Try to process local hart ipis instead of defaulting to busy wait so as to prevent deadlocks, or else just spin loop
        log::trace!("Waiting in hart {}", src_hartid);
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
                IPIRequest::RfenceIfence { src_hartid } => {
                    process_ifence_ipi(src_hartid);
                }
                _ => ipi_handling_failed(),
            }
        }
        drop(ipi_requests);
    }
    log::trace!("Done waiting in hart {}", src_hartid);
}

pub fn get_sbi_spec_version() -> usize {
    let mut spec_ver: usize;

    spec_ver = (ECALL_VERSION_MAJOR << SPEC_VERSION_MAJOR_OFFSET)
        & (SPEC_VERSION_MAJOR_MASK << SPEC_VERSION_MAJOR_OFFSET);
    spec_ver |= ECALL_VERSION_MINOR;
    println!("Computed spec_version: {:x}", spec_ver);
    return spec_ver;
}

pub fn probe(a0: usize, a6: usize) -> (isize, usize) {
    println!("probing a0 {:x}", a0);
    let mut ret: isize = 0;
    let mut out_val: usize = 0;

    match a0 {
        sbi::EXT_HSM => match a6 {
            sbi_ext_hsm::HART_SUSPEND => {
                println!("Hart_suspend");
                ret = 0;
                out_val = 1;
            }
            sbi_ext_hsm::HART_START | sbi_ext_hsm::HART_STOP | sbi_ext_hsm::HART_GET_STATUS => {
                println!("Hart start/stop/status");
                ret = 0;
                out_val = 0;
            }
            _ => ecall_handler_failed(sbi::EXT_BASE, a0),
        },
        sbi::EXT_TIME | sbi::EXT_IPI | sbi::EXT_RFENCE => {
            ret = 0;
            out_val = 1;
            println!("PROBING sbi::EXT_TIME/IPI/RFENCE.")
        }
        sbi::EXT_SRST => out_val = sbi_ext_srst_probe(a0),
        sbi_ext_base::PMU_EXT => ret = -2,
        _ => ecall_handler_failed(sbi::EXT_BASE, a0),
    }

    println!("Returning from probe {}", ret);

    return (ret, out_val);
}

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
    return ret;
}

pub fn sbi_ext_srst_probe(_a0: usize) -> usize {
    // TODO For now this function pretends that srst extension probe works as expected.
    // If needed in the future, this must be implemented fully - refer to openSBI for this.
    return 1;
}

pub fn ecall_handler_failed(_a7: usize, _a6: usize) {
    // panic!("SBI ecall not supported: a7 {:x} a6 {:x}.", _a7, _a6);
}
