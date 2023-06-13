#include <stdint.h>

#include "idt.h"
#include "gdt.h"
#include "syscall.h"
#include "segments.h"
#include "enclave_rt.h"


// ———————————————————————— Entry Point into binary ————————————————————————— //
void trusted_entry(frame_t* frame)
{
  if (frame == NULL) {
    return;
  }
  // Save the previous values.
  gdtr_t saved_gdt;
  idtr_t saved_idt;
  uint64_t sys_handler; 
  uint16_t ds, es, ss;

  save_gdt(&saved_gdt);
  //save_segments(&ds, &es, &ss); // TODO still have a problem when restoring.
  save_idt(&saved_idt);
  save_syscall(&sys_handler);

  //Set up the gdt
  gdt_assemble();
  //Set up idt handler.
  idt_init();
  //Set up syscall handler.
  syscall_init();
  //TODO call the user

  asm volatile (
      "sti\n\t"
      "mov $0, %%ebx\n\t"
      "div %%ebx\n\t"
      :
      :
      :);

  asm volatile("cli\n\t" : : : );

  // Restore the previous values.
  restore_gdt(&saved_gdt);
  //restore_segments(&ds, &es, &ss); // TODO still have a problem here.
  restore_idt(&saved_idt);
  restore_syscall(&sys_handler);
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
