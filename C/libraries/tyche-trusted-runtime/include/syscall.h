#ifndef __TRT_INCLUDE_SYSCALL_H__
#define __TRT_INCLUDE_SYSCALL_H__

#include <stdint.h>
// ———————————————————————————————— Syscalls ———————————————————————————————— //
#define ATTEST_ENCLAVE 1000
#define  PRINT 1001
#define  GATE_CALL 1002
#define WRITE 1003
#define READ 1004

// ———————————————————————————————— Linux syscall ———————————————————————————————— //
#define SBRK 1005
#define BRK 1006

// ———————————————————————————————— Linux syscall ———————————————————————————————— //
typedef unsigned long long arg_t;
typedef struct SyscallArgs {
  arg_t syscall;
  arg_t arg_1;
  arg_t arg_2;
  arg_t arg_3;
  arg_t arg_4;
}SyscallArgs;
int syscall_print(char* buff);
int syscall_enclave_attestation();
int syscall_gate_call();
int syscall_write(char* buff, int cnt);
int syscall_read(char* buff, int cnt);
void* bricks_malloc(int num_bytes);
void* bricks_free(void *p);
#endif
