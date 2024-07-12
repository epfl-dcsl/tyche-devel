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

// ————————————————————————— Application functions —————————————————————————— //

void call_tychools(nonce_t nonce, unsigned long long offset) {
  char cmd[256];
  // TODO: detect architecture to run the proper command (e.g. remove
  // --riscv-enabled on non-riscv platforms)
  sprintf(cmd,
          "sudo chmod ugo+rx tychools;./tychools attestation "
          "--att-src=file_tychools.txt --src-bin=enclave_iso --offset=0x%llx "
          "--nonce=0x%llx --riscv-enabled",
          offset, nonce);
  LOG("cmd %s", cmd);
  LOG("WARNING: for now this assume we run on RISC-V! Update code for x86");
  system(cmd);
}

void write_to_tychools(hello_world_t *msg) {
  file_tychools = fopen("file_tychools.txt", "w");
  if (file_tychools == NULL) {
    LOG("File failed to open tychools file\n");
  } else {
    LOG("Writing public key and data to tychools file\n");
    for (int i = 0; i < 32; i++) {
      uint32_t x = (uint32_t)msg->pub_key[i] & 0x0FF;
      fprintf(file_tychools, "%u\n", x);
    }
    for (int i = 0; i < 64; i++) {
      uint32_t x = (uint32_t)msg->signed_enclave_data[i] & 0x0FF;
      fprintf(file_tychools, "%u\n", x);
    }
    fclose(file_tychools);
  }
}

void read_tychools_response() {
  tychools_response = fopen("tychools_response.txt", "r");
  if (tychools_response == NULL) {
    LOG("Failed to open a reponse file");
  } else {
    LOG("Answer from tychools\n");
    char *line = NULL;
    size_t len = 0;
    while ((getline(&line, &len, tychools_response)) != -1) {
      LOG("%s", line);
    }
    fclose(tychools_response);
  }
}

/// Calls the enclave twice to print a message.
int hello_world() {
  TEST(enclave != NULL);
  TEST(shared != NULL);
  LOG("Executing HELLO_WORLD enclave\n");
  hello_world_t *msg = (hello_world_t *)(&(shared->args));

  // Call the enclave.
  if (sdk_call_domain(enclave) != SUCCESS) {
    ERROR("Unable to call the enclave %d!", enclave->handle);
    goto failure;
  }
  LOG("First enclave message:\n%s", msg->reply);

  // Generating random nonce
  const nonce_t mod = (1e9 + 7);
  nonce_t nonce = rand() % mod;
  LOG("Nonce sent by the client is %llx", nonce);
  msg->nonce = nonce;
  // Call to enclave, which will do attestation
  LOG("Calling enclave to execute attestation");
  if (sdk_call_domain(enclave) != SUCCESS) {
    ERROR("Unable to call the enclave a second time %d!", enclave->handle);
    goto failure;
  }

  write_to_tychools(msg);
  LOG("Calling the command to tychools to compare the result\n");
  //TODO: fix this.
  call_tychools(msg->nonce, /*enclave->map.physoffset*/ 0);
  read_tychools_response();

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

  // Find the shared region.
  shared = (config_t *)find_default_shared(enclave);
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
  return SUCCESS;
failure:
  return FAILURE;
}
