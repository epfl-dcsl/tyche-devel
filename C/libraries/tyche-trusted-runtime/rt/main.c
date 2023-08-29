#include <stdint.h>

#include "idt.h"
#include "gdt.h"
#include "syscall.h"
#include "segments.h"
#include "sdk_tyche_rt.h"
#include "bricks.h"

// ———————————————————————————————— Functions to do different things in trusted main  ————————————————————————————————— 

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
  syscall_write((char*)&x, sizeof(x));
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
    // syscall_gate_call();
  }

  // TODO call the user

  // __asm__ volatile("syscall");

  // make_exception();

  int nonce = 0x123;
  syscall_enclave_attestation(nonce);

  syscall_print("Tyche");

  for(int i = 0; i < 10;i++) {
    void* x = syscall_malloc(100);
    if(x == NULL) {
      syscall_print("NULL");
    }
    else {
      syscall_print("Good alloc");
    }
  }

  // void* x = syscall_malloc(100);
  // if(syscall_free(x) == 0) {
  //   syscall_print("Successfull allocation and free");
  // }
  // else {
  //   syscall_print("Alloc and free error");
  // }

  //asm volatile("cli\n\t" : : : );
}