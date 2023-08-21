#include "common.h"
#include "syscall.h"
#include <stdint.h>

// ———————————————————————————————— Interface to make syscalls ————————————————————————————————— //
void make_syscall(SyscallArgs* args){
  asm volatile(
      // Setting arguments.
      "movq %0, %%rax\n\t"
      "movq %1, %%rdi\n\t"
      "movq %2, %%rsi\n\n"
      "movq %3, %%rdx\n\t"
      "movq %4, %%r10\n\t"
      "syscall\n\t"
      :
      : "rm" (args->syscall), "rm" (args->arg_1), "rm" (args->arg_2), "rm" (args->arg_3), "rm" (args->arg_4)
      : "rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "memory");
}

extern int bricks_print_handler(char* buff);
int syscall_print(char* buff) {
  return bricks_print_handler(buff);
}

// extern int bricks_attest_enclave_hadler(int nonce);
int syscall_enclave_attestation(int nonce) {
  return bricks_attest_enclave_handler(nonce);
  SyscallArgs args;
  args.syscall = ATTEST_ENCLAVE;
  args.arg_1 = nonce;
  make_syscall(&args);
  return 0;
}

extern int bricks_gate_call_handler();
int syscall_gate_call() {
  return bricks_gate_call_handler();
  SyscallArgs args;
  args.syscall = GATE_CALL;
  make_syscall(&args);
  return 0;
}

