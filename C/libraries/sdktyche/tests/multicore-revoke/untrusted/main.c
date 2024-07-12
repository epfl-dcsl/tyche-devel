#define _GNU_SOURCE
#include "common.h"
#include "common_log.h"
#include "enclave_app.h"
#include "sdk_tyche.h"
#include "sdk_tyche_rt.h"
#include "tyche_api.h"
#include "tyche_driver.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ucontext.h>
#include <time.h>
#include <ucontext.h>
#include <pthread.h>
#include <sys/ioctl.h> 
// ————————————————————————————— Helper macros —————————————————————————————— //

#define FAILING(text) { \
  ERROR("[FAILURE]\n%s\n", text); \
  exit(-1); \
}

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

// ———————————————————————————————— Helpers ————————————————————————————————— //

/// Check that we have at least two cores so that one can run the domain.
static void check_platform_config(void) {
  if (sdk_get_core_count() < 2) {
    FAILING("Not enough cores to run the experiment");
  }
}

static void pin_to_core_id(int id) {
  pthread_t thread;
  thread = pthread_self();
  cpu_set_t affinity_mask;
  CPU_ZERO(&affinity_mask);
  CPU_SET(id, &affinity_mask);

  if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &affinity_mask) != 0) {
    ERROR("Unable to set thread affinity.");
    exit(-1);
  }
  int local_cpu_id = sched_getcpu();
  if (local_cpu_id != id) {
    ERROR("Desired cpu id is %d, got %d", id, local_cpu_id);
    FAILING("Could not setup the local cpu id.");
  }
}

void* run_domain(void* args) {
  tyche_domain_t* dom = (tyche_domain_t*) args;
  pin_to_core_id(1);
  LOG("Running the domain!");
  if (sdk_call_domain(dom) == SUCCESS) {
    FAILING("The call should not have returned with success");
  }
  return NULL;
}

static pthread_t run_on_core(tyche_domain_t* dom) {
  pthread_t thread;
  if (pthread_create(&thread, NULL, run_domain, (void*) dom) < 0) {
    FAILING("Unable to run thread for domain.");
  }
  return thread;
}

capa_index_t find_management(tyche_domain_t* dom) {
  capa_index_t res = 0; 
  if (ioctl(dom->handle, TYCHE_GET_MGMT_INDEX, &res) != SUCCESS) {
    ERROR("Unable to find the mgmt capa");
    exit(1);
  } 
  return res;
}

static void raw_revoke(tyche_domain_t* dom) {
  capa_index_t mgmt = find_management(dom);
  LOG("Found the capability! %lld", mgmt);
  // Do the raw revoke.
  if (tyche_revoke(mgmt) != SUCCESS) {
    FAILING("Revocation failed.");
  }
}

// ————————————————————————— Application functions —————————————————————————— //

tyche_domain_t* local_create_domain(char* name) {
  tyche_domain_t* dom = malloc(sizeof(tyche_domain_t));
  usize core_mask = sdk_all_cores_mask();
  if (dom == NULL) {
    FAILING("Unable to allocate domain."); 
  }
  memset(dom, 0, sizeof(tyche_domain_t));
  if (sdk_create_domain(dom, name, core_mask, ALL_TRAPS, DEFAULT_PERM) != SUCCESS) {
    FAILING("Cannot create the domain.") 
  }
  return dom;
}

// —————————————————————————————————— Main —————————————————————————————————— //
int main(int argc, char *argv[]) {
  // Initialization.
  pin_to_core_id(0);

  // Create the domain.
  tyche_domain_t* dom = local_create_domain(argv[0]);

  // Init the shared region.
  config_t* shared = find_default_shared(dom);
  if (shared == NULL) {
    FAILING("Did not find the shared region.");
  }
  shared->flag = 0;

  // Run on the other core.
  pthread_t thread = run_on_core(dom);

  // Loop until we see the magic value. 
  while(shared->flag != MAGIC_VALUE) {}
 
  LOG("The domain is up and running!");
  LOG("Deleting the domain!");
  // Now we need to attempt a raw revoke.
  // The driver would revoke all the capabilities first.
  raw_revoke(dom);
  pthread_join(thread, NULL);
  LOG("[SUCCESS] all done")
  return SUCCESS;
failure:
  return FAILURE;
}
