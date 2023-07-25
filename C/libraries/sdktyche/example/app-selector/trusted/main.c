#include "sdk_tyche_rt.h"
#include "enclave_app.h"

// ———————————————————————————————— Globals ————————————————————————————————— //
config_t* shared = NULL;

// ————————————————————— TRANSITION_BENCHMARK Functions ————————————————————— //

void transition_benchmark(frame_t* frame)
{
  transition_benchmark_t* count = (transition_benchmark_t*)(&(shared->args));
  while(1) {
    count->counter++;
    gate_call(frame);
  }
}

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

// —————————————————————————— BreakPoint Function ——————————————————————————— //

void breakpoint(frame_t* frame)
{
  // Pray we hit that exception first.
  // If this doesn't work, we'll see something else than breakpoint.
  asm volatile (
      "sti\n\t"
      "int $3\n\t"
      :
      :
      :);
}

// ———————————————————————— Dispatcher configuration ———————————————————————— //

typedef void (*encl_function)(frame_t*);

encl_function dispatcher[] = {
  transition_benchmark,
  hello_world,
  hello_world,
  breakpoint,
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
