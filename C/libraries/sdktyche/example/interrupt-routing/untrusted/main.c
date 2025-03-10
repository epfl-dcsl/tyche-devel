#define _GNU_SOURCE
#include "common.h"
#include "common_log.h"
#include "enclave_app.h"
#include "sdk_tyche.h"
#include "sdk_tyche_rt.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ucontext.h>
#include <time.h>
#include <stdbool.h>
#include <ucontext.h>

// ———————————————————————————— Local Variables ————————————————————————————— //

usize has_faulted = FAILURE;

tyche_domain_t *enclave = NULL;

config_t *shared = NULL;

FILE *file_tychools;
FILE *tychools_response;

// ———————————————————————————————— Helpers ————————————————————————————————— //

/// Looks up for the shared memory region with the enclave.
static void *find_default_shared(tyche_domain_t *enclave) {
  domain_shared_memory_t *shared_sec = NULL;
  if (enclave == NULL) {
    ERROR("Supplied enclave is null.");
    goto failure;
  }
  // Find the shared region.
  dll_foreach(&(enclave->shared_regions), shared_sec, list) {
    if (shared_sec->segment->p_type == KERNEL_SHARED) {
      return (void *)(shared_sec->untrusted_vaddr);
    }
  }
  ERROR("Unable to find the shared buffer for the enclave!");
failure:
  return NULL;
}

// ————————————————————————— Application functions —————————————————————————— //

/// Calls the enclave twice to print a message.
int run_interrupt_routing() {
  TEST(enclave != NULL);
  config_t *default_shared = (config_t*) find_default_shared(enclave);
  if (default_shared == NULL) {
    ERROR("Unable to find the default shared buffer.");
    goto failure;
  }
  LOG("Executing interrupt routing enclave\n");

  // Call the enclave.
  if (sdk_call_domain(enclave) != SUCCESS) {
      ERROR("Unable to call the enclave %d!", enclave->handle);
      goto failure;
  }
  LOG("We came back! Let's check got the correct value");
  if (default_shared->marker != 777) {
    ERROR("Wrong value, expected 777 got %d", default_shared->marker);
    goto failure;
  }
  LOG("Success!");
  // Clean up.
  if (sdk_delete_domain(enclave) != SUCCESS) {
    ERROR("Unable to delete the enclave %d", enclave->handle);
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
  usize traps[NB_TRAP_PERMS] = {0};
  memcpy(traps, ALL_TRAPS, sizeof(usize) * NB_TRAP_PERMS);

  // We use 0x80 to trigger a call back.
  // As a result we clear bit 128 in the bitmap.
  traps[2] ^= 0x1;
  traps[0] ^= ((1ULL << 32) -1);

  // Allocate the enclave.
  enclave = malloc(sizeof(tyche_domain_t));
  if (enclave == NULL) {
    ERROR("Unable to allocate enclave structure");
    goto failure;
  }
  // Init the enclave.
  if (sdk_create_domain(enclave, argv[0], core_mask, traps, DEFAULT_PERM) !=
      SUCCESS) {
    ERROR("Unable to parse the enclave");
    goto failure;
  }
  LOG("The binary enclave has been loaded!");
  LOG("Calling the enclave, good luck!");

  if (run_interrupt_routing() != SUCCESS) {
    ERROR("Oups... we received a failure... good luck debugging.");
    goto failure;
  }
  LOG("Done, have a good day!");
  return SUCCESS;
failure:
  return FAILURE;
}
