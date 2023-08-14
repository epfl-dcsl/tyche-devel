#include <stdint.h>

#include "idt.h"
#include "gdt.h"
#include "syscall.h"
#include "segments.h"
#include "sdk_tyche_rt.h"

extern int rust_function(int a, int b);

void setup_interrupts_syscalls(frame_t* frame) {
  gdtr_t saved_gdt;
  idtr_t saved_idt;
  uint64_t sys_handler; 
  uint16_t ds, es, ss;

  // Save previous values
  save_gdt(&saved_gdt);
  //save_segments(&ds, &es, &ss); // TODO still have a problem when restoring.
  save_idt(&saved_idt);
  save_syscall(&sys_handler);

  //Set up the gdt
  gdt_assemble();
  //Set up idt handler.
  idt_init(frame);
  //Set up syscall handler.
  syscall_init();
}

void divide_by_zero_exception() {
  asm volatile (
      "sti\n\t"
      "mov $0, %%ebx\n\t"
      "div %%ebx\n\t"
      :
      :
      :);
}

void call_rust() {
  int x = rust_function(28,7);
  int* shared = (int*) get_default_shared_buffer();
  *shared = x;
}

// ———————————————————————— Entry Point into binary ————————————————————————— //
void trusted_entry(frame_t* frame)
{
  if (frame == NULL) {
    return;
  }
  
  call_rust();

  gate_call(frame);
  // setup_interrupts_syscalls(frame);
  // TODO call the user

  // divide_by_zero_exception();

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
