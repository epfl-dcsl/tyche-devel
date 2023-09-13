#include <stdint.h>

#include "syscall.h"

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

void test_attestation() {
  int nonce = 0x123;
  attestation_struct_t att_struct;
  syscall_enclave_attestation(nonce, &att_struct);
}

void test_mm() {
  void* next = (void*)0;
  void* prev = (void*)0;
  for(int i = 0; i < 10;i++) {
    next = bricks_malloc(100); // one page
    if(next == prev) {
      syscall_print("NULL");
    }
    else {
      syscall_print("Good alloc");
    }
    prev = next;
  }
} 

// ———————————————————————— Entry Point into binary ————————————————————————— //
void user_main()
{
  // make_exception();
  test_attestation();
  test_mm();
  syscall_print("Tyche");  

  // TODO call the user
}