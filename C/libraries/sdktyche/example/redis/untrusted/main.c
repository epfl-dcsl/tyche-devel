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

// —————————————————————————————————— Main —————————————————————————————————— //
int main(int argc, char *argv[]) {
  // Figure out sched-affinity.
  usize core_mask = sdk_pin_to_current_core();

  // Allocate the enclave.
  enclave = malloc(sizeof(tyche_domain_t));
  if (enclave == NULL) {
    ERROR("Unable to allocate enclave structure");
    goto failure;
  }
  // Init the enclave.
  if (sdk_create_domain(enclave, argv[0], core_mask, ALL_TRAPS, DEFAULT_PERM) !=
      SUCCESS) {
    ERROR("Unable to parse the enclave");
    goto failure;
  }
  LOG("The binary enclave has been loaded!");
  if (sdk_delete_domain(enclave) != SUCCESS) {
    ERROR("Unable to delete the redis domain.");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}
