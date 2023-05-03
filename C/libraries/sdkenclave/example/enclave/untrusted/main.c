#include <string.h>
#include "common.h"
#include "enclave_rt.h"
#include "enclave_loader.h"
#include "enclave_app.h"

// ——————————————————————————————— Constants ———————————————————————————————— //

const char* ENCLAVE_PATH = "enclave";

static void* find_default_shared(enclave_t* enclave)
{
  enclave_shared_section_t* shared_sec = NULL;
  if (enclave == NULL) {
    ERROR("Supplied enclave is null.");
    goto failure;
  }
    // Find the shared region.
  dll_foreach(&(enclave->config.shared_sections), shared_sec, list) {
    if (strncmp(
          DEFAULT_SHARED_BUFFER_SECTION_NAME, 
          shared_sec->section->sh_name + enclave->parser.strings,
          strlen(DEFAULT_SHARED_BUFFER_SECTION_NAME)) == 0) {
      break;
    }
  }
  if (shared_sec == NULL) {
    ERROR("Unable to find the shared buffer for the enclave!");
    goto failure;
  }
  return (void*)(shared_sec->untrusted_vaddr);
failure:
  return NULL;
}


int main(void) {
  void* shared_buffer = NULL;
  my_encl_message_t* msg;
  enclave_t enclave;
  LOG("Let's load an enclave!");

  // Init the enclave.
  if (init_enclave(&enclave, ENCLAVE_PATH) != SUCCESS) {
    ERROR("Unable to parse the enclave '%s'", ENCLAVE_PATH);
    goto failure;
  }

  /// Get the shared buffer address.
  msg = (my_encl_message_t*) find_default_shared(&enclave);

  // Call the enclave.
  if (call_enclave(&enclave, NULL) != SUCCESS) {
    ERROR("Unable to call the enclave %lld!", enclave.handle);
    goto failure;
  }
  LOG("Here is the first message from the enclave:\n%s", msg->reply);

  // Call the enclave again.
  if (call_enclave(&enclave, NULL) != SUCCESS) {
    ERROR("Unable to call the enclave a second time %lld!", enclave.handle);
    goto failure;
  }

  LOG("Here is the second message from the enclave:\n%s", msg->reply);

  // Clean up.
  if (delete_enclave(&enclave) != SUCCESS) {
    ERROR("Unable to delete the enclave %lld", enclave.handle);
    goto failure;
  }
  LOG("All done!");
  return  0;
failure:
  return FAILURE;
}
