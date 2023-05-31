#include "idt.h"
#include "gdt.h"
#include "enclave_rt.h"

static long syscall_handler(
    unsigned long syscall_number,
    unsigned long arg1,
    unsigned long arg2,
    unsigned long arg3,
    unsigned long arg4,
    unsigned long arg5,
    unsigned long arg6);


// ———————————————————————— Entry Point into binary ————————————————————————— //
void trusted_entry(frame_t* frame)
{
  if (frame == NULL) {
    return;
  }
  //Set up the gdt
  gdt_assemble();
  //Set up idt handler.
  idt_init();
  //TODO set up syscall handler.
  //TODO call the user
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
