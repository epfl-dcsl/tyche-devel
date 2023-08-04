#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
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

FILE* file_tychools;
FILE* tychools_response;

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

void run_commands(nonce_t nonce, unsigned long long offset) {
  char cmd[256];
  sprintf(cmd, "cd crates/tychools;cargo run attestation --att-src=../../file_tychools.txt --src-bin=../../enclave_iso --offset=0x%llx --nonce=0x%x", offset, nonce);
  LOG("cmd %s", cmd);
  system(cmd);
}

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

  const nonce_t mod = (1e9 + 7);
  nonce_t nonce = rand() % mod;
  LOG("Nonce sent by the client is %llx", nonce);
  msg->nonce = nonce;
  LOG("Calling enclave to execute attestation");
  if (sdk_call_domain(enclave, NULL) != SUCCESS) {
    ERROR("Unable to call the enclave a second time %lld!", enclave->handle);
    goto failure;
  }
  file_tychools = fopen("file_tychools.txt", "w");
  if(file_tychools == NULL) {
    LOG("File failed to open tychools file\n");
  }
  else {
    LOG("Writing public key and data to tychools file\n");
    for(int i = 0;i < 32;i++) {
      uint32_t x = (uint32_t)msg->pub_key[i] & 0x0FF;
      fprintf(file_tychools, "%u\n", x);
    }
    for(int i = 0;i < 64;i++) {
      uint32_t x = (uint32_t)msg->signed_enclave_data[i] & 0x0FF;
      fprintf(file_tychools, "%u\n", x);
    }
    fclose(file_tychools);
  }
  LOG("Calling the command to tychools to compare the result\n");

  run_commands(msg->nonce, enclave->map.physoffset);

  tychools_response = fopen("tychools_response.txt", "r");
  if(tychools_response == NULL) {
    LOG("Failed to open a reponse file");
  }
  else {
    LOG("Answer from tychools\n");
    char* line = NULL;
    int len = 0;
    while ((getline(&line, &len, tychools_response)) != -1) {
        LOG("%s", line);
    }
    fclose(tychools_response);
  }

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
