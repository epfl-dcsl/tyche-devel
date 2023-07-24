#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/ucontext.h>
#include "common.h"
#include "enclave_rt.h"
#include "enclave_loader.h"
#include "sandbox_app.h"
#include "tychools.h"
#include "sdk_app.h"

// ——————————————————————————————— Constants ———————————————————————————————— //

char* const DEFAULT_ENCLAVE_PATH = "enclave";
char* enclave_path = DEFAULT_ENCLAVE_PATH; 

// ———————————————————————————— Local Variables ————————————————————————————— //

enclave_t* enclave = NULL;

config_t* shared = NULL;

// ———————————————————————————————— Helpers ————————————————————————————————— //

/// Looks up for the shared memory region with the enclave.
static void* find_default_shared(enclave_t* enclave)
{
  enclave_shared_memory_t* shared_sec = NULL;
  if (enclave == NULL) {
    ERROR("Supplied enclave is null.");
    goto failure;
  }
  // Find the shared region.
  dll_foreach(&(enclave->config.shared_sections), shared_sec, list) {
    if (shared_sec->tpe == TYCHE_SHARED_SEGMENT 
        && shared_sec->shared.segment->p_type == KERNEL_SHARED
        && shared_sec->shared.segment->p_vaddr == SHARED_BUFFER) {
      return (void*) (shared_sec->untrusted_vaddr);
      
    } 
  }
  ERROR("Unable to find the shared buffer for the enclave!");
failure:
  return NULL;
}

// ——————————————————————————— Parse application ———————————————————————————— //

/// Parse environment variable to select the correct application.
/// We default to HELLO_WORLD if the environment variable is not defined.
static application_e parse_application()
{
  char * app = getenv(ENV_APP);

  if (app == NULL) {
    goto default_app;
  }
  for (int i = 0; i <= WRITE_RO; i++) {
    if (strcmp(APP_NAMES[i], app) == 0) {
      return i;
    } 
  }
default_app:
  return WRITE_RO;

}
// ————————————————————————— Application functions —————————————————————————— //

/// Calls the enclave twice to print a message.
int write_ro()
{
  TEST(enclave != NULL);
  TEST(shared != NULL);
  TEST(shared->app == WRITE_RO);
  LOG("Executing WRITE_RO enclave\n");
  write_ro_t* msg = (write_ro_t*)(&(shared->args));
  memcpy(msg->buffer, "My saved message\0", 17);
  // Call the enclave.
  if (call_enclave(enclave, NULL) != SUCCESS) {
    ERROR("Unable to call the enclave %lld!", enclave->handle);
    goto failure;
  }
  TEST(strcmp(msg->buffer, "My saved message") == 0);
  LOG("The message is still here:\n%s", msg->buffer);
  // Clean up.
  if (delete_enclave(enclave) != SUCCESS) {
    ERROR("Unable to delete the enclave %lld", enclave->handle);
    goto failure;
  }
  LOG("All done!");
  return  SUCCESS;
failure:
  return FAILURE;
}


// ———————————————————————————— Dispatcher setup ———————————————————————————— //

typedef int (*application_tpe)(void);

application_tpe dispatcher[] = {
  write_ro,
};

// —————————————————————————————————— Main —————————————————————————————————— //
int main(int argc, char *argv[]) {
  // Allocate the enclave.
  enclave = malloc(sizeof(enclave_t));
  if (enclave == NULL) {
    ERROR("Unable to allocate enclave structure");
    goto failure;
  }
  application_e application = parse_application();
  char* loaded_enclave = NULL;

  // Init the domain.
  if (sdk_create_enclave(
        enclave, enclave_path, argv[0], &loaded_enclave,
        ALL_CORES, NO_TRAPS) != SUCCESS) {
      ERROR("Unable to parse the sandbox '%s'", enclave_path);
      goto failure;
  }
  LOG("The binary '%s' has been loaded!", loaded_enclave);

  // Find the shared region.
  shared = (config_t*) find_default_shared(enclave);
  if (shared == NULL) {
    ERROR("Unable to find the default shared region.");
    goto failure;
  }
  shared->app = application;

  LOG("Calling the application '%s', good luck!", APP_NAMES[shared->app]);
  if (dispatcher[application]() != SUCCESS) {
    ERROR("Oups... we received a failure... good luck debugging.");
    goto failure;
  }
  free(enclave);
  LOG("Done, have a good day!");
  return  SUCCESS;
failure:
  return FAILURE;
}
