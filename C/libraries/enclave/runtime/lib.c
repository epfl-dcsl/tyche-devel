#include "encl_rt.h"
#include "tyche_capabilities_types.h"
#include "tyche_api.h"

/// This symbol is patched to validate entry points.
extern void enclave_dispatch(enclave_entry_t* entry, gate_frame_t* frame);

void trusted_entry(capa_index_t ret_handle, void *args)
{
  //TODO do some checks + copy args inside enclave memory.
  gate_frame_t frame = {ret_handle, args}; 
  enclave_entry_t* entry = (enclave_entry_t*) args;

  // Call the enclave main.
  enclave_dispatch(entry, &frame); 

  // Done executing the enclave, return.
  gate_call(&frame);
  // Should never return, if we do, an exit call happens.
}


int gate_call(gate_frame_t* frame)
{
  usize result = FAILURE;
  usize vmcall = TYCHE_SWITCH;
  gate_frame_t ret_frame = {0, 0};
  asm volatile(
    "movq %3, %%rax\n\t"
    "movq %4, %%rdi\n\t"
    "movq %5, %%rsi\n\t"
    "movq %6, %%r11\n\t"
    "vmcall\n\t"
    "movq %%rax, %0\n\t"
    "movq %%rdi, %1\n\t"
    "movq %%r11, %2\n\t"
    : "=rm" (result), "=rm" (ret_frame.ret), "=rm" (ret_frame.args)
    : "rm" (vmcall), "rm" (frame->ret), "rm" (NO_CPU_SWITCH), "rm" (frame->args)
    : "rax", "rdi", "r11", "memory");
  frame->ret = ret_frame.ret;
  frame->args = ret_frame.args;
  return result;
}
