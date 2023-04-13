#include "enclave_rt.h"
#include "enclave_app.h"

const char* message = "Hello World!\n\t\0";

void my_memcpy(void* dest, void* src, int size)
{
  char* ptr_dest = (char*) dest;
  char* ptr_src = (char*) src;
  for (int i = 0; i < size; i++) {
    ptr_dest[i] = ptr_src[i];
  } 
}

void print_message(void* args)
{
  my_encl_message_t* msg = (my_encl_message_t*) get_default_shared_buffer();
  if (msg == 0) {
    int* ptr = (int*) 0xdeadbeef;
    *ptr = 0xdeadbabe;
  }
  my_memcpy(msg->reply, (void*) message, 15);
}

void trusted_entry(frame_t* frame)
{
  // Error.
  if (frame == NULL) {
    return;
  }
  print_message(frame->args);
}
