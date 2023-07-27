#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/ucontext.h>
#include "common.h"
#include "sdk_tyche_rt.h"
#include "sandbox_app.h"
#include "sdk_tyche.h"

// ———————————————————————————— Local Variables ————————————————————————————— //

tyche_domain_t* sandbox = NULL;

config_t* shared = NULL;

// ———————————————————————————————— Helpers ————————————————————————————————— //

/// Looks up for the shared memory region with the enclave.
static void* find_default_shared(tyche_domain_t* sb)
{
  domain_shared_memory_t* shared_sec = NULL;
  if (sb == NULL) {
    ERROR("Supplied enclave is null.");
    goto failure;
  }
  // Find the shared region.
  dll_foreach(&(sb->config.shared_regions), shared_sec, list) {
    if (shared_sec->segment->p_type == KERNEL_SHARED
        && shared_sec->segment->p_vaddr == SHARED_BUFFER) {
      return (void*) (shared_sec->untrusted_vaddr);
      
    } 
  }
  ERROR("Unable to find the shared buffer for the sandbox!");
failure:
  return NULL;
}

// ————————————————————————— Application functions —————————————————————————— //

/// Calls the enclave twice to print a message.
int write_ro()
{
  TEST(sandbox != NULL);
  TEST(shared != NULL);
  LOG("Executing WRITE_RO enclave\n");
  write_ro_t* msg = (write_ro_t*)(&(shared->args));
  memcpy(msg->buffer, "My saved message\0", 17);
  // Call the enclave.
  if (sdk_call_domain(sandbox, NULL) != SUCCESS) {
    ERROR("Unable to call the sandbox %d!", sandbox->handle);
    goto failure;
  }
  TEST(strcmp(msg->buffer, "My saved message") == 0);
  LOG("The message is still here:\n%s", msg->buffer);
  // Clean up.
  if (sdk_delete_domain(sandbox) != SUCCESS) {
    ERROR("Unable to delete the sandbox %d", sandbox->handle);
    goto failure;
  }
  LOG("All done!");
  return  SUCCESS;
failure:
  return FAILURE;
}

// —————————————————————————————————— Main —————————————————————————————————— //
int main(int argc, char *argv[]) {
  // Allocate the sandbox.
  sandbox = malloc(sizeof(tyche_domain_t));
  if (sandbox == NULL) {
    ERROR("Unable to allocate sandbox structure");
    goto failure;
  }
  // Init the domain.
  if (sdk_create_domain(
        sandbox, argv[0], ALL_CORES, NO_TRAPS, DEFAULT_PERM, SharedVCPU) != SUCCESS) {
      ERROR("Unable to parse the sandbox");
      goto failure;
  }
  LOG("The binary has been loaded!");

  // Find the shared region.
  shared = (config_t*) find_default_shared(sandbox);
  if (shared == NULL) {
    ERROR("Unable to find the default shared region.");
    goto failure;
  }
  LOG("Calling the sandbox, good luck!");
  if (write_ro() != SUCCESS) {
    ERROR("Oups... we received a failure... good luck debugging.");
    goto failure;
  }
  free(sandbox);
  LOG("Done, have a good day!");
  return  SUCCESS;
failure:
  return FAILURE;
}
