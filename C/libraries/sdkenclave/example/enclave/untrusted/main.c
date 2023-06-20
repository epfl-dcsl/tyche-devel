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
#include "enclave_app.h"
#include "tychools.h"
#include "sdk_app.h"

// ——————————————————————————————— Constants ———————————————————————————————— //

char* const DEFAULT_ENCLAVE_PATH = "enclave";
char* enclave_path = DEFAULT_ENCLAVE_PATH; 

// ———————————————————————————— Local Variables ————————————————————————————— //

usize has_faulted = FAILURE;

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
    if (shared_sec->tpe == TYCHE_SHARED_SECTION) {
      if (strncmp(
          DEFAULT_SHARED_BUFFER_SECTION_NAME, 
          shared_sec->shared.section->sh_name + enclave->parser.strings,
          strlen(DEFAULT_SHARED_BUFFER_SECTION_NAME)) == 0) {
        return (void*)(shared_sec->untrusted_vaddr);
      }
    } else if (shared_sec->shared.segment->p_type == KERNEL_SHARED) {
      return (void*)(shared_sec->untrusted_vaddr);
    }
  }
  ERROR("Unable to find the shared buffer for the enclave!");
failure:
  return NULL;
}

/// Handler for the malicious app.
/// It survives the illegal access and skips the instruction.
void malicious_handler(int signo, siginfo_t *info, void *uap)
{
  LOG("Handler called for address %llx", info->si_addr);
  ucontext_t *context = uap;
  //context->uc_mcontext.gregs[REG_RIP] += 6;
  has_faulted = SUCCESS;

  // Check we can call the enclave a second time.
  if (call_enclave(enclave, NULL) != SUCCESS) {
    ERROR("Failed to call the enclave a second time!");
    goto failure;
  }
  hello_world_t* msg = (hello_world_t*)(&(shared->args));
  LOG("Recovered. Second message: %s", msg->reply);

  // All good, do the cleanup.
  if (delete_enclave(enclave) != SUCCESS) {
    ERROR("Unable  to delete the enclave.");
    goto failure;
  }
   LOG("It's a success, let's exit.");
   exit(0);
failure:
  exit(1);
}

/// Handler for the breakpoint app.
void breakpoint_handler(int signal)
{
  LOG("Breakpoint handler called %d", signal);
  if (delete_enclave(enclave) != SUCCESS) {
    ERROR("Unable to delete the enclave %lld", enclave->handle);
    exit(1);
  }
  // Just quit the program
  exit(0);
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
  for (int i = 0; i <= BREAKPOINT; i++) {
    if (strcmp(APP_NAMES[i], app) == 0) {
      return i;
    } 
  }
default_app:
  return HELLO_WORLD;

}
// ————————————————————————— Application functions —————————————————————————— //

/// Calls the enclave twice to print a message.
int hello_world()
{
  TEST(enclave != NULL);
  TEST(shared != NULL);
  TEST(shared->app == HELLO_WORLD);
  LOG("Executing HELLO_WORLD enclave\n");
  hello_world_t* msg = (hello_world_t*)(&(shared->args));
  // Call the enclave.
  if (call_enclave(enclave, NULL) != SUCCESS) {
    ERROR("Unable to call the enclave %lld!", enclave->handle);
    goto failure;
  }
  LOG("First enclave message:\n%s", msg->reply);

  // Do a second call to the enclave.
  if (call_enclave(enclave, NULL) != SUCCESS) {
    ERROR("Unable to call the enclave a second time %lld!", enclave->handle);
    goto failure;
  }
  LOG("Second enclave message:\n%s", msg->reply);
  
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

/// Performs a small transition benchmark.
int transition_benchmark()
{
  TEST(enclave != NULL);
  TEST(shared != NULL);
  TEST(shared->app == TRANSITION_BENCHMARK);
  LOG("Executing TRANSITION_BENCHMARK enclave\n");
  transition_benchmark_t* msg = (transition_benchmark_t*)(&(shared->args));

  for (int i = 0; i < OUTER_LOOP_NB; i++) {
    // reset the counter.
    msg->counter = 0;
    clock_t begin = clock();
    for (int j = 0; j < INNER_LOOP_NB; j++) {
        // Call the enclave.
        if (call_enclave(enclave, NULL) != SUCCESS) {
          ERROR("Unable to call the enclave %lld!", enclave->handle);
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
  if (delete_enclave(enclave) != SUCCESS) {
    ERROR("Unable to delete the enclave %lld", enclave->handle);
    goto failure;
  }
  LOG("All done!");
  return  SUCCESS;
failure:
  return FAILURE;
}

/// Starts similar to hello world printing a first message.
/// Then, it attempts to access enclave memory.
/// This triggers a fault, which then calls the handler that skips the offending
/// instruction and survives. Note that the virtual address in the untrusted code
/// is different than the one in the enclave.
/// If everything goes well, we should be able to call the enclave a second time.
int malicious()
{
  TEST(enclave != NULL);
  TEST(shared != NULL);
  TEST(shared->app == MALICIOUS);
  LOG("Executing MALICIOUS enclave\n");
  malicious_t* msg = (malicious_t*)(&(shared->args));


  LOG("Setting a handler");
  struct sigaction action;
  action.sa_flags = SA_SIGINFO;
  action.sa_sigaction = malicious_handler;
  if (sigaction(SIGSEGV, &action, NULL) == -1) {
    ERROR("Unable to register handler");
    goto failure;
  }
  if (sigaction(SIGTRAP, &action, NULL) == -1) {
    ERROR("Unable to register second handler");
    goto failure;
  }

 // Call the enclave.
  if (call_enclave(enclave, NULL) != SUCCESS) {
    ERROR("Unable to call the enclave %lld!", enclave->handle);
    goto failure;
  }
  LOG("First enclave message:\n%s", msg->reply);

  LOG("Address we try to read: %llx", enclave->map.virtoffset);
  int * conf_ptr = (int*) (enclave->map.virtoffset);
  int a = *conf_ptr + 67;
  
  ERROR("We survived the fault (%d)", a);
failure:
  return FAILURE;
}

/// Calls the enclave to trigger a breakpoint exception.
/// This should trigger a fault, which will call our handler here.
/// The enclave in that case registers handlers for all exceptions except breakpoint.
int breakpoint()
{
  TEST(enclave != NULL);
  TEST(shared != NULL);
  TEST(shared->app == BREAKPOINT);
  LOG("Executing BREAKPOINT enclave\n");

  LOG("Setting a handler for BREAKPOINT");
  struct sigaction sa;
  sa.sa_handler = breakpoint_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  if (sigaction(SIGTRAP, &sa, NULL) == -1) {
    ERROR("Unable to register handler");
    goto failure;  
  } 

  LOG("Calling the enclave now... good luck");
  // Call the enclave.
  if (call_enclave(enclave, NULL) != SUCCESS) {
    ERROR("Unable to call the enclave %lld!", enclave->handle);
    goto failure;
  }
  /// We always fail here.
failure:
  return FAILURE;
}

// ———————————————————————————— Dispatcher setup ———————————————————————————— //

typedef int (*application_tpe)(void);

application_tpe dispatcher[] = {
  transition_benchmark,
  hello_world,
  malicious,
  breakpoint,
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

  // Init the enclave.
  if (application == BREAKPOINT) {
      if (sdk_create_enclave(
            enclave, enclave_path, argv[0], &loaded_enclave,
            ALL_CORES, ALL_TRAPS - (1 << 3)) != SUCCESS) {
      ERROR("Unable to parse the enclave: %s", enclave_path);
      goto failure;
    }
  } else {
    if (sdk_create_enclave(
          enclave, enclave_path, argv[0], &loaded_enclave,
          ALL_CORES, ALL_TRAPS) != SUCCESS) {
      ERROR("Unable to parse the enclave '%s'", enclave_path);
      goto failure;
    }
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
  LOG("Done, have a good day!");
  return  SUCCESS;
failure:
  return FAILURE;
}
