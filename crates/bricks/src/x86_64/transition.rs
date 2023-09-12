use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

static USER_RSP: AtomicU64 = AtomicU64::new(0);
static STACK_SIZE: AtomicU64 = AtomicU64::new(0x2000);
static USER_RIP: AtomicU64 = AtomicU64::new(0);

pub fn x86_64_transition_setup(user_rip: u64, user_rsp: u64) {
    USER_RIP.store(user_rip, Ordering::Relaxed);
    USER_RSP.store(user_rsp, Ordering::Relaxed);
}

pub fn transition_into_user_mode() {
    let stack_selector: u64 = 0x23;
    let stack_pointer: u64 = USER_RSP.load(Ordering::Relaxed) + STACK_SIZE.load(Ordering::Relaxed);
    let code_selector: u64 = 0x1b;
    let instr_pointer: u64 = USER_RIP.load(Ordering::Relaxed);
    unsafe {
        asm!(
            "push {0:r}",
            "push {1:r}",
            "pushf",
            "push {2:r}",
            "push {3:r}",
            "iretq", //iret ?
            in(reg) stack_selector,
            in(reg) stack_pointer,
            in(reg) code_selector,
            in(reg) instr_pointer,
        );
    }
}
