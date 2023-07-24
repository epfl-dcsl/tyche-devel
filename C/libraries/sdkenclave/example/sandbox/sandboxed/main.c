#include "enclave_rt.h"
#include "sandbox_app.h"

// ———————————————————————————————— Globals ————————————————————————————————— //
config_t* shared = NULL;

// ————————————————————————— HELLO_WORLD Functions —————————————————————————— //

const char* message = "Hello World!\n\t\0";

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
  write_ro_t* msg = (write_ro_t*) (&(shared->args));
  if (msg == 0) {
    int* ptr = (int*) 0xdeadbeef;
    *ptr = 0xdeadbabe;
  }
  my_memcpy(msg->buffer, input, 15);
}

void write_ro(frame_t* frame)
{
  print_message((void*) message);
}

// ———————————————————————— Dispatcher configuration ———————————————————————— //

typedef void (*encl_function)(frame_t*);

encl_function dispatcher[] = {
  write_ro,
};


// ————————————————————————————— Entry Function ————————————————————————————— //

void trusted_entry(frame_t* frame)
{
  // Error.
  if (frame == NULL) {
    return;
  }
  shared = (config_t*) get_default_shared_buffer();
  dispatcher[shared->app](frame);
}
