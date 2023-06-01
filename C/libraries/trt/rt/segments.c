#include <stdint.h>
#include "common.h"

// ——————————————————————————————— Functions ———————————————————————————————— //
int save_segments(uint16_t* ds, uint16_t* es, uint16_t* ss)
{
  if (ds == NULL || es == NULL || ss == NULL) {
    goto failure;
  }
  __asm__ __volatile__(
      "mov %%ds, %0\n\t"
      "mov %%es, %1\n\t"
      "mov %%ss, %2\n\t"
      : "=m"(*ds), "=m"(*es), "=m"(*ss)
      :
      : "memory");
  return SUCCESS;
failure:
  return FAILURE;
}

int restore_segments(uint16_t* ds, uint16_t* es, uint16_t* ss)
{
  if (ds == NULL || es == NULL || ss == NULL) {
    goto failure;
  }
  __asm__ __volatile__(
      "mov %0, %%ds\n\t"
      "mov %1, %%es\n\t"
      "mov %2, %%ss\n\t"
      :
      : "rm"(*ds), "rm"(*es), "rm"(*ss)
      : "memory");
  return SUCCESS;
failure:
  return FAILURE;
  
}
