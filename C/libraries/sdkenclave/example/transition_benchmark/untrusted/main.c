#include <string.h>
#include <time.h>
#include "common.h"
#include "enclave_rt.h"
#include "enclave_loader.h"
#include "enclave_app.h"

// ——————————————————————————————— Constants ———————————————————————————————— //

#define OUTER_LOOP_NB (10)

#define INNER_LOOP_NB (1000)

const char* ENCLAVE_PATH = "bench_enclave";

// ———————————————————————————— Local Functions ————————————————————————————— //

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

// —————————————————————————————— Main Program —————————————————————————————— //

int main(void) {
  void* shared_buffer = NULL;
  my_encl_counter_t* msg;
  enclave_t enclave;
  LOG("We will run %d times %d transitions!", OUTER_LOOP_NB, INNER_LOOP_NB);

  // Init the enclave.
  if (init_enclave(&enclave, ENCLAVE_PATH) != SUCCESS) {
    ERROR("Unable to parse the enclave '%s'", ENCLAVE_PATH);
    goto failure;
  }

  /// Get the shared buffer address.
  msg = (my_encl_counter_t*) find_default_shared(&enclave);

  for (int i = 0; i < OUTER_LOOP_NB; i++) {
    // reset the counter.
    msg->counter = 0;
    clock_t begin = clock();
    for (int j = 0; j < INNER_LOOP_NB; j++) {
        // Call the enclave.
        if (call_enclave(&enclave, NULL) != SUCCESS) {
          ERROR("Unable to call the enclave %lld!", enclave.handle);
          goto failure;
        }
    }
    clock_t end = clock();
    double time_spent = (double)(end-begin)/CLOCKS_PER_SEC;
    if (msg->counter != INNER_LOOP_NB) {
      ERROR("We expected counter %llx, got %llx", INNER_LOOP_NB, msg->counter);
    }
    LOG("Run %d: %d call-return in %.6f seconds", i, INNER_LOOP_NB, time_spent);
  }

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
