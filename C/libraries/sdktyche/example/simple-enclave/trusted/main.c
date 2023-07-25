#include "sdk_tyche_rt.h"
#include "enclave_app.h"

// ———————————————————————————————— Globals ————————————————————————————————— //
config_t* shared = NULL;

// ————————————————————————— HELLO_WORLD Functions —————————————————————————— //

const char* message = "Hello World!\n\t\0";
const char* message2= "Bye Bye! :)!\n\t\0";

void my_memcpy(void* dest, void* src, int size)
{
  char* ptr_dest = (char*) dest;
  char* ptr_src = (char*) src;
  for (int i = 0; i < size; i++) {
    ptr_dest[i] = ptr_src[i];
  } 
}

void print_message(void* input)
{
  hello_world_t* msg = (hello_world_t*) (&(shared->args));
  if (msg == 0) {
    int* ptr = (int*) 0xdeadbeef;
    *ptr = 0xdeadbabe;
  }
  my_memcpy(msg->reply, input, 15);
}

void hello_world(frame_t* frame)
{
  print_message((void*) message);
  // Do a return.
  gate_call(frame);
  // We're back, print the second message.
  print_message((void*) message2);
}

// ————————————————————————————— Entry Function ————————————————————————————— //

void trusted_entry(frame_t* frame)
{
  // Error.
  if (frame == NULL) {
    return;
  }
  shared = (config_t*) get_default_shared_buffer();
  hello_world(frame);
}
