#ifndef __TRT_INCLUDE_SYSCALL_H__
#define __TRT_INCLUDE_SYSCALL_H__

#include <stdint.h>
// ———————————————————————————————— Syscalls ———————————————————————————————— //
#define ATTEST_ENCLAVE 1000
#define  PRINT 1001
#define WRITE 1002
#define READ 1003

// ———————————————————————————————— Linux syscall ———————————————————————————————— //
#define SBRK 1004
#define BRK 1005

// ———————————————————————————————— Syscall structs ———————————————————————————————— //

#define PUB_KEY_SIZE 32
#define SIGNED_DATA_SIZE 64
typedef struct {
  char pub_key[PUB_KEY_SIZE];
  char signed_enclave_data[SIGNED_DATA_SIZE];
} attestation_struct_t;

typedef unsigned long long arg_t;
typedef struct SyscallArgs {
  arg_t syscall;
  arg_t arg_1;
  arg_t arg_2;
  arg_t arg_3;
  arg_t arg_4;
}SyscallArgs;
// ———————————————————————————————— Syscall functions ———————————————————————————————— //
int syscall_print(char* buff);
int syscall_enclave_attestation(int nonce, attestation_struct_t* att_struct);
int syscall_write(char* buff, int cnt);
int syscall_read(char* buff, int cnt);
void* bricks_malloc(int num_bytes);
void* bricks_free(void *p);
#endif
