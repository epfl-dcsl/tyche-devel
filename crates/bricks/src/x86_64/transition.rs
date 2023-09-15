use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::syscall_handlers::BRICKS_RSP;
static USER_RSP_START: AtomicU64 = AtomicU64::new(0);
static STACK_SIZE: AtomicU64 = AtomicU64::new(0x2000);
static USER_RIP_START: AtomicU64 = AtomicU64::new(0);

const STACK_SELECTOR: u64 = 0x1b;
const CODE_SELECTOR: u64 = 0x23;

pub fn x86_64_transition_setup(user_rip: u64, user_rsp: u64) {
    USER_RIP_START.store(user_rip, Ordering::Relaxed);
    USER_RSP_START.store(user_rsp, Ordering::Relaxed);
}

pub fn transition_into_user_mode() {
    unsafe {
        asm!("mov {}, rsp", out(reg)BRICKS_RSP);
    }
    let stack_selector: u64 = STACK_SELECTOR;
    let stack_pointer: u64 =
        USER_RSP_START.load(Ordering::Relaxed) + STACK_SIZE.load(Ordering::Relaxed);
    let code_selector: u64 = CODE_SELECTOR;
    let instr_pointer: u64 = USER_RIP_START.load(Ordering::Relaxed);
    unsafe {
        asm!(
            "pushq {0:r}",
            "pushq {1:r}",
            "pushf",
            "pushq {2:r}",
            "pushq {3:r}",
            "iretq",
            in(reg) stack_selector,
            in(reg) stack_pointer,
            in(reg) code_selector,
            in(reg) instr_pointer,
            options(att_syntax)
        );
    }
}
