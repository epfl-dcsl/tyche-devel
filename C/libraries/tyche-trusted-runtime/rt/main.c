#include <stdint.h>

#include "idt.h"
#include "gdt.h"
#include "syscall.h"
#include "segments.h"
#include "sdk_tyche_rt.h"
#include "bricks.h"

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
    bricks_gate_call();
  }
  
  // setup_interrupts_syscalls();

  // TODO call the user

  make_exception();

  //asm volatile("cli\n\t" : : : );
}

/*
#define SYSCALL_MSR 0x00000174

unsigned long long read_msr(unsigned int msr)
{
    unsigned int low, high;
    asm volatile("rdmsr" : "=a" (low), "=d" (high) : "c" (msr));
    return ((unsigned long long)high << 32) | low;
}

int main()
{
    unsigned long long syscall_msr_value = read_msr(SYSCALL_MSR);
    printf("SYSCALL MSR value: 0x%llx\n", syscall_msr_value);
    return 0;
}
*/
