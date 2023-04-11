#include "tyche_api.h"
#include "enclave_rt.h"
// ———————————————————————————— Enclave sections ———————————————————————————— //

///@warn these string constants must be the same as in enclave_rt.h
#ifdef DEFAULT_SHARED_BUFFER 
__attribute__((section(".tyche_shared_default_buffer")))
char shared_buffer[DEFAULT_SHARED_BUFFER_SIZE];
#endif

__attribute__((section(".tyche_enclave_stack")))
char enclave_stack[DEFAULT_STACK_SIZE];

// ————————————————————————————————— Hooks —————————————————————————————————— //
/// Entry point defined by the application.
extern void trusted_entry(frame_t* frame); 

// ——————————————————————————————— Functions ———————————————————————————————— //
//
void trusted_main(capa_index_t ret_handle, void *args)
{
  frame_t frame = {ret_handle, args}; 
 
  // Call the enclave main.
  trusted_entry(&frame); 

  // Done executing the enclave, return.
  gate_call(&frame);
  // Should never return, if we do, an exit call happens.
}

int gate_call(frame_t* frame)
{
  usize result = FAILURE;
  usize vmcall = TYCHE_SWITCH;
  frame_t ret_frame = {0, 0};
  asm volatile(
    "movq %3, %%rax\n\t"
    "movq %4, %%rdi\n\t"
    "movq %5, %%rsi\n\t"
    "movq %6, %%r11\n\t"
    "vmcall\n\t"
    "movq %%rax, %0\n\t"
    "movq %%rdi, %1\n\t"
    "movq %%r11, %2\n\t"
    : "=rm" (result), "=rm" (ret_frame.ret_handle), "=rm" (ret_frame.args)
    : "rm" (vmcall), "rm" (frame->ret_handle), "rm" (NO_CPU_SWITCH), "rm" (frame->args)
    : "rax", "rdi", "r11", "memory");
  frame->ret_handle = ret_frame.ret_handle;
  frame->args = ret_frame.args;
  return result;
}
