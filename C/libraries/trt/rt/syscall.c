#include "common.h"
#include "syscall.h"
#include <stdint.h>

int save_syscall(uint64_t* to_save)
{
  uint32_t msr_low, msr_high;
  if (to_save == NULL) {
    goto failure;
  } 
  __asm__ __volatile__(
      "rdmsr"
      : "=a" (msr_low), "=d" (msr_high)
      : "c" (LSTAR));
  *to_save = ((uint64_t) msr_high) << 32 | msr_low;
  return 0;
failure:
  return FAILURE;
}

int restore_syscall(uint64_t* to_restore)
{
  uint32_t low, high;
  if (to_restore == NULL) {
    goto failure;
  }
  low = *to_restore & MASK32;
  high = ((*to_restore) >> 32) & MASK32;
  __asm__ __volatile__(
    "wrmsr"
    :
    : "c"(LSTAR), "a"(low), "d"(high)
    : "memory");

  return SUCCESS;
failure:
  return FAILURE;
}

int syscall_init()
{
  uint32_t low, high;
  low = ((uint64_t) syscall_handler) & MASK32;
  high = (((uint64_t) syscall_handler) >> 32) & MASK32;
  __asm__ __volatile__(
    "wrmsr"
    :
    : "c"(LSTAR), "a"(low), "d"(high)
    : "memory");
  return SUCCESS;
}

int syscall_handler(
    uint64_t syscall_number,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5,
    uint64_t arg6)
{
  //TODO implement
  return FAILURE;
}
