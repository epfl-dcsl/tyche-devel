#include "common.h"
#include "syscall.h"
#include <stdint.h>

// ———————————————————————————————— Interface to make syscalls ————————————————————————————————— //

// #define SYSCALL_0(which) SYSCALL(which, 0, 0, 0, 0, 0)
// #define SYSCALL_1(which, arg0) SYSCALL(which, arg0, 0, 0, 0, 0)
// #define SYSCALL_2(which, arg0, arg1) SYSCALL(which, arg0, arg1, 0, 0, 0)
// #define SYSCALL_3(which, arg0, arg1, arg2) \
//   SYSCALL(which, arg0, arg1, arg2, 0, 0)
// #define SYSCALL_4(which, arg0, arg1, arg2, arg3) \
//   SYSCALL(which, arg0, arg1, arg2, arg3, 0)
// #define SYSCALL_5(which, arg0, arg1, arg2, arg3, arg4) \
//   SYSCALL(which, arg0, arg1, arg2, arg3, arg4)

int syscall_print() {
  return 0;
}

extern int bricks_attest_enclave_hadler(int nonce);
int syscall_enclave_attestation(int nonce) {
  return bricks_attest_enclave_handler(nonce);
}

extern int bricks_gate_call_handler();
int syscall_gate_call() {
  return bricks_gate_call_handler();
}

// ———————————————————————————————— Ported to Bricks ————————————————————————————————— //

// int save_syscall(uint64_t* to_save)
// {
//   uint32_t msr_low, msr_high;
//   if (to_save == NULL) {
//     goto failure;
//   } 
//   __asm__ __volatile__(
//       "rdmsr"
//       : "=a" (msr_low), "=d" (msr_high)
//       : "c" (LSTAR));
//   *to_save = ((uint64_t) msr_high) << 32 | msr_low;
//   return 0;
// failure:
//   return FAILURE;
// }

// int restore_syscall(uint64_t* to_restore)
// {
//   uint32_t low, high;
//   if (to_restore == NULL) {
//     goto failure;
//   }
//   low = *to_restore & MASK32;
//   high = ((*to_restore) >> 32) & MASK32;
//   __asm__ __volatile__(
//     "wrmsr"
//     :
//     : "c"(LSTAR), "a"(low), "d"(high)
//     : "memory");

//   return SUCCESS;
// failure:
//   return FAILURE;
// }

// int syscall_init()
// {
//   uint32_t low, high;
//   low = ((uint64_t) syscall_handler) & MASK32;
//   high = (((uint64_t) syscall_handler) >> 32) & MASK32;
//   __asm__ __volatile__(
//     "wrmsr"
//     :
//     : "c"(LSTAR), "a"(low), "d"(high)
//     : "memory");
//   return SUCCESS;
// }

// int syscall_handler(
//     uint64_t syscall_number,
//     uint64_t arg1,
//     uint64_t arg2,
//     uint64_t arg3,
//     uint64_t arg4,
//     uint64_t arg5,
//     uint64_t arg6)
// {
//   //TODO implement
//   __asm__ volatile("cli; hlt");
//   return FAILURE;
// }