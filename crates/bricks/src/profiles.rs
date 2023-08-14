enum SyscallsBehave {
    HANDLE,
    KILL,
    IGNORE,
}

const NUM_OF_SYSCALLS : u32 = 256;

pub struct SyscallProfile {
    handle_syscalls : SyscallsBehave,
    syscalls_to_handle : [NUM_OF_SYSCALLS;SyscallsBehave],
}

enum InterruptsBehave {
    TYCHE_FORWARD,
    KILL,
    IGNORE,
}

const NUM_OF_INTERRUPTS : u32 = 256;

pub struct InterruptsProfile {
    handle_interrupts : InterruptsBehave,
    interrupts_to_handle : [NUM_OF_INTERRUPTS;InterruptsBehave],
}