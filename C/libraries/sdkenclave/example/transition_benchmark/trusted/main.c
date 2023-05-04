#include "enclave_rt.h"
#include "enclave_app.h"

void main_loop(my_encl_counter_t* count, frame_t* frame)
{
  while(1) {
    count->counter++;
    // Do a return
    gate_call(frame);
  }
}

void trusted_entry(frame_t* frame)
{
  // Error.
  if (frame == NULL) {
    return;
  }
  my_encl_counter_t* count = (my_encl_counter_t*) get_default_shared_buffer();
  if (count == 0) {
    int* ptr = (int*) 0xdeadbeef;
    *ptr = 0xdeadbabe;
  }
  main_loop(count, frame);
}
