#include "tyche_api.h"
#include "enclave_rt.h"
// ———————————————————————————— Enclave sections ———————————————————————————— //


#ifdef TYCHOOLS
/// This is introduced by tychools.
char *shared_buffer = (char*) 0x300000; 
#else
///@warn these string constants must be the same as in enclave_rt.h
__attribute__((section(".tyche_shared_default_buffer")))
__attribute__ ((aligned (0x1000)))
char shared_buffer[DEFAULT_SHARED_BUFFER_SIZE];

__attribute__((section(".tyche_enclave_stack")))
__attribute__ ((aligned (0x1000)))
char enclave_stack[DEFAULT_STACK_SIZE];
#endif

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

extern int asm_call_gate(capa_index_t* capa, void** args);

int gate_call(frame_t* frame)
{
  usize result = FAILURE;
  //usize vmcall = TYCHE_SWITCH;
  //frame_t ret_frame = {0, 0};


  result = asm_call_gate(&(frame->ret_handle), &(frame->args));

  /*
  asm volatile(
    // Saving registers.
    "pushq %%rbp\n\t"
    //"pushq %%rbx\n\t"
    //"pushq %%rcx\n\t"
    //"pushq %%rdx\n\t"
    //"pushq %%r10\n\t"
    //"pushq %%r11\n\t"
    //"pushq %%r12\n\t"
    //"pushq %%r13\n\t"
    //"pushq %%r14\n\t"
    //"pushq %%r15\n\t"
    "pushfq\n\t"
    // Setting arguments for the call.
    "movq %3, %%rax\n\t"
    "movq %4, %%rdi\n\t"
    "movq %5, %%r11\n\t"
    "vmcall\n\t"
    "movq %%rax, %0\n\t"
    "movq %%rdi, %1\n\t"
    "movq %%r11, %2\n\t"
    // Restoring registers.
    "popfq\n\t"
    //"popq %%r15\n\t"
    //"popq %%r14\n\t"
    //"popq %%r13\n\t"
    //"popq %%r12\n\t"
    //"popq %%r11\n\t"
    //"popq %%r10\n\t"
    //"popq %%rdx\n\t"
    //"popq %%rcx\n\t"
    //"popq %%rbx\n\t"
    "popq %%rbp\n\t"
    : "=rm" (result), "=rm" (ret_frame.ret_handle), "=rm" (ret_frame.args)
    : "rm" (vmcall), "rm" (frame->ret_handle), "rm" (frame->args)
    : "rax", "rdi", "r11", "memory");
  frame->ret_handle = ret_frame.ret_handle;
  frame->args = ret_frame.args;*/
  return result;
}

void* get_default_shared_buffer()
{
  return (void*) (shared_buffer);
}
