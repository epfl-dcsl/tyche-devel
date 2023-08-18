#include <stdint.h>

#include "idt.h"
#include "gdt.h"
#include "syscall.h"
#include "segments.h"
#include "sdk_tyche_rt.h"
#include "bricks.h"

void divide_by_zero_exception() {
  asm volatile (
      "sti\n\t"
      "mov $0, %%ebx\n\t"
      "div %%ebx\n\t"
      :
      :
      :);
}

void int_exception() {
  asm volatile (
      "sti\n\t"
      "int $1\n\t"
      :);
}

void make_exception() {
  divide_by_zero_exception();
  // int_exception();
}

void call_bricks(int a, int b) {
  int x = bricks_function(a,b);
  int* shared = (int*) bricks_get_default_shared_buffer();
  *shared = x;
}

// ———————————————————————— Entry Point into binary ————————————————————————— //
void trusted_entry(frame_t* frame)
{
  if (frame == NULL) {
    return;
  }
  const int num_of_calls = 10;
  for(int i = 0; i < num_of_calls;i++) {
    call_bricks(2*i, 3*i);
    syscall_gate_call();
  }
  
  // setup_interrupts_syscalls();

  // TODO call the user

  // make_exception();
  int nonce = 0x123;
  syscall_enclave_attestation(nonce);
  syscall_gate_call();

  //asm volatile("cli\n\t" : : : );
}

// ———————————————————————— Ported to bricks ————————————————————————— //
// void setup_interrupts_syscalls() {
//   gdtr_t saved_gdt;
//   idtr_t saved_idt;
//   uint64_t sys_handler; 
//   uint16_t ds, es, ss;

//   // Save previous values
//   save_gdt(&saved_gdt);
//   //save_segments(&ds, &es, &ss); // TODO still have a problem when restoring.
//   save_idt(&saved_idt);
//   save_syscall(&sys_handler);

//   //Set up the gdt
//   gdt_assemble();
//   //Set up idt handler.
//   idt_init();
//   //Set up syscall handler.
//   syscall_init();
// }