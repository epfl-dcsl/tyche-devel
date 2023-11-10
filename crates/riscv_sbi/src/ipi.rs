use core::arch::asm;
use core::sync::atomic::Ordering;

use riscv_utils::{
    set_mip_ssip, ACLINT_MSWI_BASE_ADDR, ACLINT_MSWI_WORD_SIZE, HART_IPI_SYNC, IPI_TYPE_SMODE,
    IPI_TYPE_TLB,
};

use crate::ecall::HART_IPI_BUFFER;
use crate::rfence::{local_ifence, local_sfence_vma_asid};
use crate::IPIRequest;

pub fn aclint_mswi_send_ipi(target_hartid: usize) {
    let target_addr: usize = ACLINT_MSWI_BASE_ADDR + target_hartid * ACLINT_MSWI_WORD_SIZE;
    unsafe {
        asm!("sw {}, 0({})", in(reg) 1, in(reg) target_addr);
    }
}

pub fn aclint_mswi_clear_ipi(target_hartid: usize) {
    let target_addr: usize = ACLINT_MSWI_BASE_ADDR + target_hartid * ACLINT_MSWI_WORD_SIZE;
    unsafe {
        asm!("sw {}, 0({})", in(reg) 0, in(reg) target_addr);
    }
}

pub fn process_ipi(current_hartid: usize) {
    aclint_mswi_clear_ipi(current_hartid);

    if IPI_TYPE_SMODE[current_hartid].load(Ordering::SeqCst) {
        IPI_TYPE_SMODE[current_hartid].store(false, Ordering::SeqCst);
        set_mip_ssip();
    }

    if IPI_TYPE_TLB[current_hartid].load(Ordering::SeqCst) {
        IPI_TYPE_TLB[current_hartid].store(false, Ordering::SeqCst);
        process_tlb_ipis(current_hartid);
    }
}

pub fn process_tlb_ipis(current_hartid: usize) {
    let mut ipi_requests = HART_IPI_BUFFER[current_hartid].lock();

    while let Some(ipi_req) = ipi_requests.pop() {
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

pub fn process_ifence_ipi(src_hartid: usize) {
    local_ifence();
    HART_IPI_SYNC[src_hartid].fetch_sub(1, Ordering::SeqCst);
}

pub fn process_tlb_ipi(src_hartid: usize, start: usize, size: usize, asid: usize) {
    local_sfence_vma_asid(start, size, asid);
    HART_IPI_SYNC[src_hartid].fetch_sub(1, Ordering::SeqCst);
}

pub fn ipi_handling_failed() {
    log::debug!("Cannot handle IPI!");
}
