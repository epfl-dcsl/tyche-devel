
#define _GNU_SOURCE
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/ucontext.h>
#include "common.h"
#include "enclave_rt.h"
#include "enclave_loader.h"
#include "enclave_app.h"

// ——————————————————————————————— Constants ———————————————————————————————— //

const char* ENCLAVE_PATH = "enclave";

usize has_faulted = FAILURE;

// ———————————————————————————— Local functions ————————————————————————————— //

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

void handler(int signo, siginfo_t *info, void *uap)
{
  LOG("Handler called for address %llx", info->si_addr);
  ucontext_t *context = uap;
  context->uc_mcontext.gregs[REG_RIP] += 6;
  has_faulted = SUCCESS;
  //abort();
}
// —————————————————————————————————— Main —————————————————————————————————— //
int main(void) {
  void* shared_buffer = NULL;
  my_encl_message_t* msg;
  enclave_t enclave;


  LOG("Set a handler");
  struct sigaction action;
  action.sa_flags = SA_SIGINFO;
  action.sa_sigaction = handler;
  if (sigaction(SIGSEGV, &action, NULL) == -1) {
    ERROR("Unable to register handler");
    goto failure;
  }

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

  LOG("Address we try to write to %llx", enclave.map.virtoffset);

  // Now attempt illegal access.
  int *conf_ptr = (int*) (enclave.map.virtoffset);
  *conf_ptr = 0x666;

  if (has_faulted != SUCCESS) {
    LOG("Haven't been caught writting the address, here is the message: '%s'", msg->reply);
    ERROR("We managed to write to confidential address!");
    goto failure;
  }
  
  // Call the enclave again, to check it still works.
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
