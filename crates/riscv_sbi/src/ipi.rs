use core::arch::asm;
use riscv_utils::{set_mip_ssip, ACLINT_MSWI_BASE_ADDR, ACLINT_MSWI_WORD_SIZE};

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

pub fn process_ipi() {
    //Note: Currently only considering the case of sbi_ipi_process_smode - not sure how in openSBI's
    //sbi_ipi_send_raw, the ipi_type is determined/updated. I can just create my own metadata in Tyche to
    //convey this information across harts - I just need to understand when to trigger which types
    //of ipis. Until then, it's all processed as follows and chances are that it may lead to
    //unexpected behaviour at times - I will debug that on a need basis. 
    let target_hartid: usize; 
    unsafe {
        asm!("csrr {}, mhartid", out(reg) target_hartid);
    }
    aclint_mswi_clear_ipi(target_hartid);
    set_mip_ssip();
}
