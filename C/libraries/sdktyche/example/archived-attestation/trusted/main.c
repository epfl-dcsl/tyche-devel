#include "sdk_tyche_rt.h"
#include "common.h"
#include "enclave_app.h"
#include "tyche_api.h"
// ———————————————————————————————— Globals ————————————————————————————————— //
config_t* shared = NULL;


// ————————————————————————————— Static define —————————————————————————————— //

static int tyche_domain_attestation(usize nonce, unsigned long long* ans, int mode) {
  vmcall_frame_t frame = {
    .vmcall = 20,
    .arg_1 = nonce,
    .arg_2 = mode,
  };
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  
  ans[0] = frame.value_1;
  ans[1] = frame.value_2;
  ans[2] = frame.value_3;
  ans[3] = frame.value_4;
  ans[4] = frame.value_5;
  ans[5] = frame.value_6;
  
  return SUCCESS;
failure:
  return FAILURE;
}

// ————————————————————————— HELLO_WORLD Functions —————————————————————————— //

const char* message = "Hello World!\n\t\0";
const char* message2 = "Bye Bye! :)!\n\t\0";
const char* message3 = "Done attestation!\n\t\0";

void put_bytes_in_arr(char* arr, unsigned long long val) {
  for(int i = 0; i < 8;i++) {
    char c = (char)(val & 0xFF);
    *arr = c;
    arr++;
    val>>=8;
  }
}

void tyche_call_wrapper(usize nonce, hello_world_t* ans, int mode) {
  unsigned long long vals[6];
  tyche_domain_attestation(nonce, vals, mode);
  if(mode == CALC_REPORT) {
    put_bytes_in_arr(ans->pub_key, vals[0]);
    put_bytes_in_arr(ans->pub_key + 8, vals[1]);
    put_bytes_in_arr(ans->pub_key + 16, vals[2]);
    put_bytes_in_arr(ans->pub_key + 24, vals[3]);
    put_bytes_in_arr(ans->signed_enclave_data, vals[4]);
    put_bytes_in_arr(ans->signed_enclave_data + 8, vals[5]);
  }
  else if(mode == READ_REPORT) {
    put_bytes_in_arr(ans->signed_enclave_data + 16, vals[0]);
    put_bytes_in_arr(ans->signed_enclave_data + 24, vals[1]);
    put_bytes_in_arr(ans->signed_enclave_data + 32, vals[2]);
    put_bytes_in_arr(ans->signed_enclave_data + 40, vals[3]);
    put_bytes_in_arr(ans->signed_enclave_data + 48, vals[4]);
    put_bytes_in_arr(ans->signed_enclave_data + 56, vals[5]);
  }
}

void my_memcpy(void* dest, void* src, int size)
{
  char* ptr_dest = (char*) dest;
  char* ptr_src = (char*) src;
  for (int i = 0; i < size; i++) {
    ptr_dest[i] = ptr_src[i];
  }
  ptr_dest[size] = '\0';
}

void print_message(void* input, int size)
{
  hello_world_t* msg = (hello_world_t*) (&(shared->args));
  if (msg == 0) {
    int* ptr = (int*) 0xdeadbeef;
    *ptr = 0xdeadbabe;
  }
  my_memcpy(msg->reply, input, size);
}

void hello_world(void)
{
  hello_world_t* msg = (hello_world_t*) (&(shared->args));
  print_message((void*) message, 15);
  // Do a return.
  gate_call();

  nonce_t nonce = msg->nonce;
  tyche_call_wrapper(nonce, msg, CALC_REPORT);
  tyche_call_wrapper(nonce, msg, READ_REPORT);
  print_message((void*)message3, 20);
}

// ————————————————————————————— Entry Function ————————————————————————————— //

void trusted_entry(void)
{
  shared = (config_t*) get_default_shared_buffer();
  hello_world();
}
