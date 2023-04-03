#include "my_shared.h"
#include "encl_rt.h"

const char* message = "Hello World!\n\t";

char encl_stack[0x4000] __attribute__((section(".encl_stack")));

void my_memcpy(void* dest, void* src, int size)
{
  char* ptr_dest = (char*) dest;
  char* ptr_src = (char*) src;
  for (int i = 0; i < size; i++) {
    ptr_dest[i] = ptr_src[i];
  } 
}

void print_message(void* source)
{
  my_encl_message_t* msg = (my_encl_message_t*) source;
  my_memcpy(msg->reply, msg->message, msg->message_len);
}

int fibonnacci(int n)
{
  if (n <= 0) {
    return 0;
  } else if (n == 1) {
    return 1;
  }
  return (fibonnacci(n-1) + fibonnacci(n-2));
}

void fibonnacci_top(void* args) {
  my_fib_message_t* msg = (my_fib_message_t*) args;
  fibonnacci(msg->value);
  my_memcpy(msg->reply, "Done with fib\n", 14);
}


void enclave_dispatch(enclave_entry_t* entry, gate_frame_t* frame)
{
  // Error.
  if (entry == NULL) {
    return;
  } else if (entry->function == NULL || entry->function == print_message) {
    print_message(entry->args);
  } else if (entry->function == fibonnacci_top) {
    fibonnacci_top(entry->args);
  }
}

// Just to look good for the compiler.
int _start() {
    /* exit system call */
    asm("movl $1,%eax;"
        "xorl %ebx,%ebx;"
        "int  $0x80"
    );
}
