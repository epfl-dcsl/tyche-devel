use lazy_static::lazy_static;

use crate::syscalls::NUM_OF_SYSCALLS;
enum SyscallsBehave {
    HANDLE,
    KILL,
    IGNORE,
}
pub struct SyscallProfile {
    handle_syscalls: SyscallsBehave,
}

enum InterruptsBehave {
    TYCHE_FORWARD,
    IGNORE,
}
const NUM_OF_INTERRUPTS: u32 = 256;
pub struct InterruptsProfile {
    handle_interrupts: InterruptsBehave,
}

enum ExceptionsBehave {
    KILL,
    IGNORE,
}
const NUM_OF_EXCEPTIONS: usize = 32;
pub struct ExceptionsProfile {
    handle_exceptions: ExceptionsBehave,
}

#[cfg(not(exceptions_behave))]
fn configure_exceptions(prof: &mut ExceptionsProfile) {
    prof.handle_exceptions = ExceptionsBehave::KILL;
}

#[cfg(exceptions_behave = "ignore")]
fn configure_exceptions(prof: &mut ExceptionsProfile) {
    prof.handle_exceptions = ExceptionsBehave::IGNORE;
}

#[cfg(not(interrupts_behave))]
fn configure_interrupts(prof: &mut InterruptsProfile) {
    prof.handle_interrupts = InterruptsBehave::TYCHE_FORWARD;
}

#[cfg(interrupts_behave = "ignore")]
fn configure_interrupts(prof: &mut InterruptsProfile) {
    prof.handle_interrupts = InterruptsBehave::IGNORE;
}

#[cfg(not(syscalls_behave))]
fn configure_syscalls(prof: &mut SyscallProfile) {
    prof.handle_syscalls = SyscallsBehave::HANDLE;
}

#[cfg(syscalls_behave = "kill")]
fn configure_syscalls(prof: &mut SyscallProfile) {
    prof.handle_syscalls = SyscallsBehave::KILL;
}

#[cfg(syscalls_behave = "ignore")]
fn configure_syscalls(prof: &mut SyscallProfile) {
    prof.handle_syscalls = SyscallsBehave::IGNORE;
}

lazy_static! {
    static ref EXCEPTION_PROFILE: ExceptionsProfile = {
        let mut exc_prof = ExceptionsProfile {
            handle_exceptions: ExceptionsBehave::KILL,
        };
        configure_exceptions(&mut exc_prof);
        exc_prof
    };
}

lazy_static! {
    static ref SYSCALLS_PROFILE: SyscallProfile = {
        let mut sys_prof = SyscallProfile {
            handle_syscalls: SyscallsBehave::HANDLE,
        };
        configure_syscalls(&mut sys_prof);
        sys_prof
    };
}

lazy_static! {
    static ref INTERRUPTS_PROFILE: InterruptsProfile = {
        let mut int_prof = InterruptsProfile {
            handle_interrupts: InterruptsBehave::TYCHE_FORWARD,
        };
        configure_interrupts(&mut int_prof);
        int_prof
    };
}

pub fn check_syscalls_kill() -> bool {
    match SYSCALLS_PROFILE.handle_syscalls {
        SyscallsBehave::KILL => {
            return true;
        }
        _ => {
            return false;
        }
    }
}

pub fn check_exceptions_kill() -> bool {
    match EXCEPTION_PROFILE.handle_exceptions {
        ExceptionsBehave::KILL => {
            return true;
        }
        _ => {
            return false;
        }
    }
}

pub fn check_exceptions_ignore() -> bool {
    match EXCEPTION_PROFILE.handle_exceptions {
        ExceptionsBehave::IGNORE => {
            return true;
        }
        _ => {
            return false;
        }
    }
}
