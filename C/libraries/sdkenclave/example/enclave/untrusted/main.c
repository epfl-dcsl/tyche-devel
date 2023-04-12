#include <string.h>
#include "common.h"
#include "enclave_rt.h"
#include "enclave_loader.h"
#include "enclave_app.h"

// ——————————————————————————————— Constants ———————————————————————————————— //

const char* ENCLAVE_PATH = "enclave";


int main(void) {
  enclave_shared_section_t* shared_sec = NULL;
  void* shared_buffer = NULL;
  my_encl_message_t* msg;
  enclave_t enclave;
  LOG("Let's load an enclave!");
  if (parse_enclave(&enclave, ENCLAVE_PATH) != SUCCESS) {
    ERROR("Unable to parse the enclave '%s'", ENCLAVE_PATH);
    goto failure;
  }

  if (load_enclave(&enclave) != SUCCESS) {
    ERROR("Unable to load the enclave '%s'", ENCLAVE_PATH);
    goto failure;
  }
  
  // Find the shared region.
  dll_foreach(&(enclave.config.shared_sections), shared_sec, list) {
    if (strncmp(
          DEFAULT_SHARED_BUFFER_SECTION_NAME, 
          shared_sec->section->sh_name + enclave.parser.strings,
          strlen(DEFAULT_SHARED_BUFFER_SECTION_NAME)) == 0) {
      break;
    }
  }
  if (shared_sec == NULL) {
    ERROR("Unable to find the shared buffer for the enclave!");
    goto failure;
  }
  /// Get the shared buffer address.
  shared_buffer = (void*)(shared_sec->untrusted_vaddr);
  LOG("We have shared memory with the enclave at %llx", shared_buffer);
  msg = (my_encl_message_t*) shared_buffer;

  if (call_enclave(&enclave, shared_buffer) != SUCCESS) {
    ERROR("Unable to call the enclave %lld!", enclave.handle);
    goto failure;
  } 
  LOG("Here is the message from the enclave %s", msg->reply);

  if (delete_enclave(&enclave) != SUCCESS) {
    ERROR("Unable to delete the enclave %lld", enclave.handle);
    goto failure;
  }
  LOG("All done!");
  return  0;
failure:
  return FAILURE;
}
