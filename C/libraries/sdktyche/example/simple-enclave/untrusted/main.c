#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/ucontext.h>
#include "common.h"
#include "sdk_tyche_rt.h"
#include "sdk_tyche.h"
#include "enclave_app.h"

// ———————————————————————————— Local Variables ————————————————————————————— //

usize has_faulted = FAILURE;

tyche_domain_t* enclave = NULL;

config_t* shared = NULL;

// ———————————————————————————————— Helpers ————————————————————————————————— //

/// Looks up for the shared memory region with the enclave.
static void* find_default_shared(tyche_domain_t* enclave)
{
  domain_shared_memory_t* shared_sec = NULL;
  if (enclave == NULL) {
    ERROR("Supplied enclave is null.");
    goto failure;
  }
  // Find the shared region.
  dll_foreach(&(enclave->config.shared_regions), shared_sec, list) {
      if (shared_sec->segment->p_type == KERNEL_SHARED) {
        return (void*)(shared_sec->untrusted_vaddr);
      }
  }
  ERROR("Unable to find the shared buffer for the enclave!");
failure:
  return NULL;
}

// ————————————————————————— Application functions —————————————————————————— //

/// Calls the enclave twice to print a message.
int hello_world()
{
  TEST(enclave != NULL);
  TEST(shared != NULL);
  LOG("Executing HELLO_WORLD enclave\n");
  hello_world_t* msg = (hello_world_t*)(&(shared->args));
  // Call the enclave.
  if (sdk_call_domain(enclave, NULL) != SUCCESS) {
    ERROR("Unable to call the enclave %d!", enclave->handle);
    goto failure;
  }
  LOG("First enclave message:\n%s", msg->reply);

  // Do a second call to the enclave.
  if (sdk_call_domain(enclave, NULL) != SUCCESS) {
    ERROR("Unable to call the enclave a second time %lld!", enclave->handle);
    goto failure;
  }
  LOG("Second enclave message:\n%s", msg->reply);
  
  // Clean up.
  if (sdk_delete_domain(enclave) != SUCCESS) {
    ERROR("Unable to delete the enclave %lld", enclave->handle);
    goto failure;
  }
  LOG("All done!");
  return  SUCCESS;
failure:
  return FAILURE;
}


// —————————————————————————————————— Main —————————————————————————————————— //
int main(int argc, char *argv[]) {
  // Allocate the enclave.
  enclave = malloc(sizeof(tyche_domain_t));
  if (enclave == NULL) {
    ERROR("Unable to allocate enclave structure");
    goto failure;
  }
  // Init the enclave.
    if (sdk_create_domain(
          enclave, argv[0],
          DEFAULT_CORES, ALL_TRAPS, DEFAULT_PERM, CopyVCPU) != SUCCESS) {
      ERROR("Unable to parse the enclave");
      goto failure;
    }
  LOG("The binary enclave has been loaded!");

  // Find the shared region.
  shared = (config_t*) find_default_shared(enclave);
  if (shared == NULL) {
    ERROR("Unable to find the default shared region.");
    goto failure;
  }
  LOG("Calling the enclave, good luck!");

  if (hello_world() != SUCCESS) {
    ERROR("Oups... we received a failure... good luck debugging.");
    goto failure;
  }
  LOG("Done, have a good day!");
  return  SUCCESS;
failure:
  return FAILURE;
}
