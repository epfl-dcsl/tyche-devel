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

int syscall_print(char* buff) {
  SyscallArgs args;
  args.syscall = PRINT;
  args.arg_1 = (arg_t)buff;
  make_syscall(&args);
  return 0;
}

int syscall_enclave_attestation(int nonce, attestation_struct_t* att_struct) {
  SyscallArgs args;
  args.syscall = ATTEST_ENCLAVE;
  args.arg_1 = nonce;
  args.arg_2 = (arg_t)att_struct;
  make_syscall(&args);
  return 0;
}

int syscall_write(char* buff, int cnt) {
  SyscallArgs args;
  args.syscall = WRITE;
  args.arg_1 = (arg_t)buff;
  args.arg_2 = (arg_t)cnt;
  make_syscall(&args);
  return 0;
}

int syscall_read(char* buff, int cnt) {
  SyscallArgs args;
  args.syscall = READ;
  args.arg_1 = (arg_t)buff;
  args.arg_2 = (arg_t)cnt;
  make_syscall(&args);
  return 0;
}

void* bricks_malloc(int num_bytes) {
  SyscallArgs args;
  args.syscall = SBRK;
  args.arg_1 = (arg_t)num_bytes;
  make_syscall(&args);
  return 0;
}

void* bricks_free(void* p) {
  SyscallArgs args;
  args.syscall = BRK;
  args.arg_1 = (arg_t)p;
  make_syscall(&args);
  return 0;
}