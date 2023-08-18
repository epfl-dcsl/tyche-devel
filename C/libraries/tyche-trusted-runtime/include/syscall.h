#ifndef __TRT_INCLUDE_SYSCALL_H__
#define __TRT_INCLUDE_SYSCALL_H__

#include <stdint.h>

// —————————————————————— Constant addresses for MSRs ——————————————————————— //

/// The RIP syscall entry for 64 bit software.
#define LSTAR ((uint64_t)0xC0000082)
/// The RIP syscall entry for compatibility mode
#define CSTAR ((uint64_t)0xC0000083)
/// low 32 bits syscall flag mask, if a bit is set, clear the corresponding one
/// in RFLAGS.
#define SFMASK_VAL ((uint64_t)0xC0000084)
/// Mask for the low/high bits of msr.
#define MASK32 ((uint64_t)0xFFFFFFFF)

// ——————————————————————————————— Functions ———————————————————————————————— //
int syscall_init();
int save_syscall(uint64_t* to_save);
int restore_syscall(uint64_t* to_restore);
int syscall_handler(
    uint64_t syscall_number,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5,
    uint64_t arg6);

// ———————————————————————————————— Syscalls ————————————————————————————————
int syscall_print();
int syscall_enclave_attestation();
int syscall_gate_call();
#endif
