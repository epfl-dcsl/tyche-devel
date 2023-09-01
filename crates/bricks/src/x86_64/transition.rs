static mut USER_RIP : u64 = 0;
// TODO fix this witht tychools
static mut USER_RSP : u64 = 0;

extern "C" {
    fn user_main();
}

pub fn x86_64_transition_setup() {
    unsafe {
        USER_RIP = user_main as u64;
    }
}