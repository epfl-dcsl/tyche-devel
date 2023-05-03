#include "tyche_api.h"
#include "common.h"

/// Simple generic vmcall implementation.
int tyche_call(vmcall_frame_t* frame)
{
  usize result = FAILURE;
#if defined(CONFIG_X86) || defined(__x86_64__)
  asm volatile(
    "movq %7, %%rax\n\t"
    "movq %8, %%rdi\n\t"
    "movq %9, %%rsi\n\n"
    "movq %10, %%rdx\n\t"
    "movq %11, %%rcx\n\t"
    "movq %12, %%r8\n\t"
    "movq %13, %%r9\n\t"
    "vmcall\n\t"
    "movq %%rax, %0\n\t"
    "movq %%rdi, %1\n\t"
    "movq %%rsi, %2\n\t"
    "movq %%rdx, %3\n\t"
    "movq %%rcx, %4\n\t"
    "movq %%r8,  %5\n\t"
    "movq %%r9,  %6\n\t"
    : "=rm" (result), "=rm" (frame->value_1), "=rm" (frame->value_2), "=rm" (frame->value_3), "=rm" (frame->value_4), "=rm" (frame->value_5), "=rm" (frame->value_6)
    : "rm" (frame->vmcall), "rm" (frame->arg_1), "rm" (frame->arg_2), "rm" (frame->arg_3), "rm" (frame->arg_4), "rm" (frame->arg_5), "rm" (frame->arg_6) 
    : "rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "memory");
#elif defined(CONFIG_RISCV) || defined(__riscv)
  //TODO(neelu)
  TEST(0);
#endif
  return (int)result;
} 

int tyche_create_domain(capa_index_t* management) {
  vmcall_frame_t frame;
  if (management == NULL) {
    goto fail;
  }
  frame.vmcall = TYCHE_CREATE_DOMAIN;
  if (tyche_call(&frame) != SUCCESS) {
    goto fail;
  }
  *management = frame.value_1;
  return SUCCESS;
fail:
  return FAILURE;
}

int tyche_seal(
    capa_index_t* transition, 
    capa_index_t management,
    usize cr3,
    usize rip, 
    usize rsp)
{
  vmcall_frame_t frame = {
    .vmcall = TYCHE_SEAL_DOMAIN,
    .arg_1 = management,
    .arg_2 = cr3, 
    .arg_3 = rip,
    .arg_4 = rsp,
  };
  if (transition == NULL) {
    goto failure;
  }

  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  *transition = frame.value_1;
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_segment_region(
    capa_index_t capa,
    capa_index_t* left,
    capa_index_t* right,
    usize start1,
    usize end1,
    usize prot1,
    usize start2,
    usize end2,
    usize prot2)
{
  vmcall_frame_t frame = {
    TYCHE_SEGMENT_REGION,
    capa,
    start1,
    end1,
    start2,
    end2,
    (prot1 << 32 | prot2),
  };
  if (left == NULL || right == NULL) {
    goto failure;
  }
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  } 
  *left = frame.value_1;
  *right = frame.value_2;
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_send(capa_index_t dest, capa_index_t capa) {
  vmcall_frame_t frame = {
    .vmcall = TYCHE_SEND,
    .arg_1 = capa,
    .arg_2 = dest,
  };
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  // Check that the revocation handle is the original one.
  if (frame.value_1 != capa) {
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

// TODO: do not exist anymore in v3!
int tyche_share(
    capa_index_t* left,
    capa_index_t dest,
    capa_index_t capa,
    usize a1,
    usize a2,
    usize a3)
{
  vmcall_frame_t frame = {
    .vmcall = TYCHE_SHARE,
    .arg_1 = dest,
    .arg_2 = capa,
    .arg_3 = a1,
    .arg_4 = a2,
    .arg_5 = a3
  };
  if (left == NULL || tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  *left = frame.value_1; 
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_duplicate(capa_index_t* new_capa, capa_index_t capa) {
  vmcall_frame_t frame = {
   .vmcall = TYCHE_DUPLICATE, 
  };
  if (new_capa == NULL || tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  *new_capa = frame.arg_1;

  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_revoke(capa_index_t id)
{
  vmcall_frame_t frame = {
    .vmcall = TYCHE_REVOKE,
    .arg_1 = id,
  };
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_switch(capa_index_t transition_handle, void* args)
{
  usize result = FAILURE;
  vmcall_frame_t frame = {
    .vmcall = TYCHE_SWITCH,
    .arg_1 = transition_handle,
    .arg_3 = (usize) args, // TODO: not yet handled by v3
  };
  DEBUG("About to switch from the capability lib: handle %lld", transition_handle);

#if defined(CONFIG_X86) || defined(__x86_64__)
  asm volatile(
    "cli \n\t"
    "movq %2, %%rax\n\t"
    "movq %3, %%rdi\n\t"
    "movq %4, %%rsi\n\t"
    "movq %5, %%r11\n\t"
    "vmcall\n\t"
    "movq %%rax, %0\n\t"
    "movq %%rdi, %1\n\t"
    : "=rm" (result), "=rm" (frame.value_1)
    : "rm" (frame.vmcall), "rm" (frame.arg_1), "rm" (frame.arg_2), "rm" (frame.arg_3)
    : "rax", "rdi", "rsi", "r11", "memory");
#elif defined(CONFIG_RISCV) || defined(__riscv)
  //TODO(neelu)
  TEST(0);
#endif
  return result;
}
