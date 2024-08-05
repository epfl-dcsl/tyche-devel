#define _GNU_SOURCE
#include "common.h"
#include "common_log.h"
#include "sandbox_app.h"
#include "sdk_tyche.h"
#include "sdk_tyche_rt.h"
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ucontext.h>
#include <time.h>
#include <ucontext.h>

// luca: very simple example

// ———————————————————————————— Local Variables ————————————————————————————— //

tyche_domain_t *sandbox = NULL;

config_t *shared = NULL;

// ———————————————————————————————— Helpers ————————————————————————————————— //

/// Looks up for the shared memory region with the enclave.
static void *find_default_shared(tyche_domain_t *sb) {
  domain_shared_memory_t *shared_sec = NULL;
  if (sb == NULL) {
    ERROR("Supplied enclave is null.");
    goto failure;
  }
  // Find the shared region.
  dll_foreach(&(sb->shared_regions), shared_sec, list) {
    if (shared_sec->segment->p_type == KERNEL_SHARED &&
        shared_sec->segment->p_vaddr == SHARED_BUFFER) {
      return (void *)(shared_sec->untrusted_vaddr);
    }
  }
  ERROR("Unable to find the shared buffer for the sandbox!");
failure:
  return NULL;
}

// ————————————————————————— Application functions —————————————————————————— //

/// Calls the enclave twice to print a message.
int write_ro() {
  TEST(sandbox != NULL);
  TEST(shared != NULL);
  LOG("Executing WRITE_RO enclave\n");
  while(1) {
    write_ro_t *msg = (write_ro_t *)(&(shared->args));
    memcpy(msg->buffer, "My saved message\0", 17);
    LOG("Wrote the message");
    // Call the enclave.
    if (sdk_call_domain(sandbox) != SUCCESS) {
      ERROR("Unable to call the sandbox %d!", sandbox->handle);
      goto failure;
    }
    LOG("The sandbox has return.");
    TEST(strcmp(msg->buffer, "My saved message") == 0);
    LOG("The message is still here:\n%s", msg->buffer);
    sleep(1);
  }
  LOG("Calling sdk_delete_domain")
  // Clean up.
  if (sdk_delete_domain(sandbox) != SUCCESS) {
    ERROR("Unable to delete the sandbox %d", sandbox->handle);
    goto failure;
  }
  LOG("All done!");
  return SUCCESS;
failure:
  return FAILURE;
}

// —————————————————————————————————— Main —————————————————————————————————— //
int main(int argc, char *argv[]) {
  // Figure out sched-affinity.
  usize core_mask = sdk_pin_to_current_core();
  // Allocate the sandbox.
  sandbox = malloc(sizeof(tyche_domain_t));
  if (sandbox == NULL) {
    ERROR("Unable to allocate sandbox structure");
    goto failure;
  }
  // Init the domain.
  if (sdk_create_domain(sandbox, argv[0], core_mask, NO_TRAPS, DEFAULT_PERM) !=
      SUCCESS) {
    ERROR("Unable to parse the sandbox");
    goto failure;
  }
  LOG("The binary has been loaded!");

  // Find the shared region.
  shared = (config_t *)find_default_shared(sandbox);
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
  return SUCCESS;
failure:
  return FAILURE;
}
