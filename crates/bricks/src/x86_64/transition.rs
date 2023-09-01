static mut USER_RIP: u64 = 0;
use core::arch::asm;
// this is fixed by tychools
static mut USER_RSP: u64 = 0x900000;
pub const STACK_SIZE: u64 = 0x2000;

extern "C" {
    fn user_main();
}

pub fn setup_rsp(user_rsp: u64) {
    unsafe {
        USER_RSP = user_rsp;
    }
}

pub fn x86_64_transition_setup() {
    unsafe {
        USER_RIP = user_main as u64;
    }
}

pub fn transition_into_user_mode() {
    let stack_selector: u64 = 0x23;
    let stack_pointer: u64;
    let code_selector: u64 = 0x1b;
    let instr_pointer: u64;
    unsafe {
        instr_pointer = USER_RIP;
        stack_pointer = USER_RSP + STACK_SIZE;
    }
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
