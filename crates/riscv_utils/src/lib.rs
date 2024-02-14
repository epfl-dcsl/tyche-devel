#![no_std]

use core::arch::asm;

use core::sync::atomic::{AtomicBool, AtomicUsize};

pub const NUM_HARTS: usize = 2;
pub const AVAILABLE_HART_MASK: usize = 0x3;

//uart base address
pub const SERIAL_PORT_BASE_ADDRESS: usize = 0x1000_0000;

//SIFIVE TEST SYSCON
pub const SIFIVE_TEST_SYSCON_BASE_ADDRESS: usize = 0x100000;
pub const SIFIVE_TEST_SYSCON_SIZE: usize = 0x1000;

//plic address and size
pub const PLIC_BASE_ADDRESS: usize = 0xc000000;
pub const PLIC_SIZE: usize = 0x600000;

//pci address and size
pub const PCI_BASE_ADDRESS: usize = 0x30000000;
pub const PCI_SIZE: usize = 0x10000000;

pub const PAGING_MODE_SV48: usize = 0x9000000000000000;

pub const ACLINT_MSWI_BASE_ADDR: usize = 0x2000000;
pub const ACLINT_MSWI_WORD_SIZE: usize = 4; 

const FALSE: AtomicBool = AtomicBool::new(false);
//Todo: Replace with num_cores
pub static HART_START: [AtomicBool; NUM_HARTS] = [FALSE; NUM_HARTS];

const ZERO: AtomicUsize = AtomicUsize::new(0);

pub static HART_START_ADDR: [AtomicUsize; NUM_HARTS] = [ZERO; NUM_HARTS];
pub static HART_START_ARG1: [AtomicUsize; NUM_HARTS] = [ZERO; NUM_HARTS]; 

pub static HART_IPI_SYNC: [AtomicUsize; NUM_HARTS] = [ZERO; NUM_HARTS];

pub static IPI_TYPE_SMODE: [AtomicBool; NUM_HARTS] = [FALSE; NUM_HARTS];
pub static IPI_TYPE_TLB: [AtomicBool; NUM_HARTS] = [FALSE; NUM_HARTS];

#[derive(Copy, Clone, Debug)]
pub struct RegisterState {
    pub ra: usize,
    pub a0: isize,
    pub a1: isize,
    pub a2: usize,
    pub a3: usize,
    pub a4: usize,
    pub a5: usize,
    pub a6: usize,
    pub a7: usize,
    pub t0: usize,
    pub t1: usize,
    pub t2: usize,
    pub t3: usize,
    pub t4: usize,
    pub t5: usize,
    pub t6: usize,
    pub zero: usize,
    pub gp: usize,
    pub tp: usize,
    pub s0: usize,
    pub s1: usize,
    pub s2: usize,
    pub s3: usize,
    pub s4: usize,
    pub s5: usize,
    pub s6: usize,
    pub s7: usize,
    pub s8: usize,
    pub s9: usize,
    pub s10: usize,
    pub s11: usize,
    //pub mepc: usize,
    //pub mstatus: usize,
}

impl RegisterState {
    pub const fn const_default() -> RegisterState {
        RegisterState {
            ra: 0,
            a0: 0,
            a1: 0,
            a2: 0,
            a3: 0,
            a4: 0,
            a5: 0,
            a6: 0,
            a7: 0,
            t0: 0,
            t1: 0,
            t2: 0,
            t3: 0,
            t4: 0,
            t5: 0,
            t6: 0,
            zero: 0,
            tp: 0,
            gp: 0,
            s0: 0,
            s1: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            s5: 0,
            s6: 0,
            s7: 0,
            s8: 0,
            s9: 0,
            s10: 0,
            s11: 0,
        }
    }
}

pub fn read_mscratch() -> usize {
    let mut mscratch: usize;

    unsafe {
        asm!("csrr {}, mscratch", out(reg) mscratch);
    }

    return mscratch;
}

pub fn write_mscratch(mscratch: usize) {
    unsafe {
        asm!("csrw mscratch, {}", in(reg) mscratch);
    }
}

pub fn read_mepc() -> usize {
    let mut mepc: usize;

    unsafe {
        asm!("csrr {}, mepc", out(reg) mepc);
    }

    return mepc;
}

pub fn write_mepc(mepc: usize) {
    unsafe {
        asm!("csrw mepc, {}", in(reg) mepc);
    }
}

pub fn read_satp() -> usize {
    let mut satp: usize;

    unsafe {
        asm!("csrr {}, satp", out(reg) satp);
    }

    return satp;
}

pub fn write_satp(satp: usize) {
    unsafe {
        asm!("csrw satp, {}", in(reg) satp);
        asm!("sfence.vma");
    }
}

pub fn write_ra(ra: usize) {
    unsafe {
        asm!("mv ra, {}", in(reg) ra);
    }
}

pub fn write_sp(sp: usize) {
    unsafe {
        asm!("mv sp, {}", in(reg) sp);
    }
}

pub fn clear_mstatus_xie() {
    unsafe {
        asm!(
            "li t0, 0xa",
            "not t1, t0",
            "csrr t2, mstatus",
            "and t2, t2, t1",
            "csrw mstatus, t2",
        );
    }
}

pub fn clear_mstatus_spie() {
    unsafe {
        asm!(
            "li t0, 0x20",
            "not t1, t0",
            "csrr t2, mstatus",
            "and t2, t2, t1",
            "csrw mstatus, t2",
        );
    }
}

pub fn clear_mideleg() {
    unsafe {
        asm!("li t0, 0", "csrw mideleg, t0",);
    }
}

pub fn disable_supervisor_interrupts() {
    unsafe {
        asm!(
            "li t0, 0x222",
            "not t1, t0",
            "csrr t2, mie",
            "and t2, t2, t1",
            "csrw mie, t2",
        );
    }
}

pub fn toggle_supervisor_interrupts() {
    unsafe {
        asm!(
            "li t0, 0x222",
            "csrr t1, mie",
            "xor t1, t1, t0",
            "csrw mie, t1",
        );
    }
}

pub fn clear_medeleg() {
    unsafe {
        asm!("li t0, 0", "csrw medeleg, t0",);
    }
}

pub fn read_medeleg() -> usize {
    let mut medeleg: usize;

    unsafe {
        asm!("csrr {}, medeleg", out(reg) medeleg);
    }

    return medeleg;
}

pub fn write_medeleg(medeleg: usize) {
    unsafe {
        asm!("csrw medeleg, {}", in(reg) medeleg);
    }
}

pub fn set_mip_ssip() {
    let mut mip: usize;

    unsafe {
        asm!("csrr {}, mip", out(reg) mip);
    }

    mip = mip | 0x2;    //Note: Assuming MIE.SEIE is set. Not sure if a check is needed. 

    unsafe {
        asm!("csrw mip, {}", in(reg) mip);
    }
}

/* pub fn aclint_mswi_send_ipi(target_hartid: usize) {
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
} */
