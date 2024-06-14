#include "sdk_tyche_rt.h"
#include "common.h"
#include "tyche_api.h"
#include "enclave_app.h"
// ———————————————————————————————— Globals ————————————————————————————————— //
config_t* shared = NULL;
// ————————————————————————— Static define  —————————————————————————— //
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

static int tyche_domain_attestation_size(unsigned long long* val){
	vmcall_frame_t frame = {
		.vmcall = 23,
	};
	if (tyche_call(&frame) != SUCCESS) {
		goto failure;
	}

	*val = frame.value_1;

	return SUCCESS;
failure:
	return FAILURE;
}


// ————————————————————————— HELLO_WORLD Functions —————————————————————————— //
//

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

static void tyche_attestation_size(hello_world_t* ans) {
  unsigned long long val;
  tyche_domain_attestation_size(&val);
  ans->report_size = val;
  //Sanity check on the size of the attestation
  if(val!=SUPPOSED_ATTESTATION_SIZE){
    val = 0;
  }
}

void tyche_call_wrapper(usize nonce, hello_world_t* ans, int mode) {
  unsigned long long vals[6];
  tyche_domain_attestation(nonce, vals, mode);
  //Sanity check on the size of the attestation
  if(!(ans->report_size)){
    return;
  }
  //Sanity check on whether we already are out of bound
  if (6*8*mode>(993)){
    return;
  }
  //Check whether we can fill 48 bytes worth of stuff or not
  if (6*8*(mode+1)>(993)){
   put_bytes_in_arr(((char *) &(ans->tpm_attestation))+96, vals[0]);
   put_bytes_in_arr(((char *) &(ans->tpm_attestation))+104, vals[1]);
   put_bytes_in_arr(((char *) &(ans->tpm_attestation))+112, vals[2]);
   put_bytes_in_arr(((char *) &(ans->tpm_attestation))+120, vals[3]);
   *(((char *) &(ans->tpm_attestation))+128) = (char) (vals[4] & 0x0FF);
  }
  char* start_address = ((char*) &(ans->pub_key)) + 6*8*mode;
  for(int i=0; i<6; i++){
    put_bytes_in_arr(start_address, vals[i]);
    start_address +=8;
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

  //The current implementation passes data from/to the application through registers.
  //Ideally, the report is passed through shared memory and would require only one call to Tyche.
  

  //Sample call to retrieve the size of the attestation in case it's unknown.
  tyche_attestation_size(msg);
  //For our use case, 22 calls to Tyche to retrieve the entire enclave report
  for(int i=0; i<22;i++){
	 tyche_call_wrapper(nonce, msg, i);
  }

  print_message((void*)message3, 20);
}

// ————————————————————————————— Entry Function ————————————————————————————— //

void trusted_entry(void)
{
  shared = (config_t*) get_default_shared_buffer();
  hello_world();
}
