#include <stdint.h>

#include "syscall.h"

// ———————————————————————————————— Functions to do different things in trusted main  ————————————————————————————————— 

// produces divide by zero exception, Bricks should catch it and exit
void divide_by_zero_exception() {
  asm volatile (
      "sti\n\t"
      "mov $0, %%ebx\n\t"
      "div %%ebx\n\t"
      :
      :
      :);
}

// produces int exception, Bricks should catch it and exit
void int_exception() {
  asm volatile (
      "sti\n\t"
      "int $1\n\t"
      :);
}

// function to choose one of the above exceptions
void make_exception() {
  divide_by_zero_exception();
  // int_exception();
}

// function to test the attestation
void test_attestation() {
  int nonce = 0x123;
  attestation_struct_t att_struct;
  syscall_enclave_attestation(nonce, &att_struct);
}

// function that tests memory management
// based on number of pages granted to Bricks
// it should print NULL at some point
void test_mm() {
  void* next = (void*)0;
  void* prev = (void*)0;
  for(int i = 0; i < 10;i++) {
    next = bricks_sbrk(100); // one page
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

void user_main() {
  syscall_print("Tyche");
  syscall_print("Tyche 2");
}

// Calls user main, after it finishes makes the exit system call
void user_main_wrapper() {
  user_main();
  syscall_exit();
  // Shouldn't return here, hlt if we do
  asm volatile("hlt"); //this will produce exception
}