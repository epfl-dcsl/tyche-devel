#include <stdint.h>

#include "syscall.h"
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

void test_sum() {
  const int num_of_calls = 10;
  for(int i = 0; i < num_of_calls;i++) {
    call_bricks(2*i, 3*i);
    // syscall_gate_call();
  }
}

void test_attestation() {
  int nonce = 0x123;
  syscall_enclave_attestation(nonce);
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
void trusted_entry()
{
  test_sum();
  // make_exception();
  test_attestation();
  test_mm();
  syscall_print("Tyche");  
  // TODO call the user
  // __asm__ volatile("syscall");

  //asm volatile("cli\n\t" : : : );
}