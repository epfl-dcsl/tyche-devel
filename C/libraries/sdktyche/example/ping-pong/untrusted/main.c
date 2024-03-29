#include <string.h>
#define _GNU_SOURCE
#include "common.h"
#include "common_log.h"
#include "ping_pong.h"
#include "sdk_tyche.h"
#include "sdk_tyche_rt.h"
#include "tyche_capabilities_types.h"
#include <stdio.h>

// Enclaves file names.
static const char* ping_name = "ping_enclave";
static const char* pong_name = "pong_enclave";

static const char* default_message =	"You spin round round\n"
																			"Baby right round,\n"
																			"Like a record baby,\n"
																			"Round round\n";


// ———————————————————————————— Helper functions ———————————————————————————— //

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
int main(int argc, char *argv[]) {
	tyche_domain_t* ping = NULL;
	tyche_domain_t* pong = NULL;
	info_t* ping_info = NULL;
	info_t* pong_info = NULL;
	// Attempt to load both enclaves.
	// For the moment to run on the same core.
	usize core_mask = sdk_pin_to_current_core();

	// Allocate ping and pong.
	ping = malloc(sizeof(tyche_domain_t));
	if (ping == NULL) {
		LOG("Unable to allocate ping.");
		goto failure;
	}
	pong = malloc(sizeof(tyche_domain_t));
	if (pong == NULL) {
		LOG("Unable to allocate pong.");
		goto failure;
	}
	if (sdk_create_domain(ping, ping_name, core_mask, ALL_TRAPS,
				DEFAULT_PERM) != SUCCESS) {
		ERROR("Unable to parse the ping enclave.");
		goto failure;
	}
	if (sdk_create_domain(pong, pong_name, core_mask, ALL_TRAPS,
				DEFAULT_PERM) != SUCCESS) {
		ERROR("Unable to parse the pong enclave");
		goto failure;
	}
	// Find the shared regions and setup the message and message sizes.
	ping_info = (info_t*) find_default_shared(ping);
	if (ping_info == NULL) {
		ERROR("Unable to find the default shared region for ping");
	}
	memset(ping_info, 0, sizeof(info_t));
	ping_info->msg_size = strlen(default_message) +1;
	memcpy(ping_info->msg_buffer, default_message, strlen(default_message) + 1);

	pong_info = (info_t*) find_default_shared(pong);
	if (pong_info == NULL) {
		ERROR("Unable to find the default shared region for pong");
		goto failure;
	}
	pong_info->msg_size = strlen(default_message) + 1;

	// TODO: make the enclaves runs on separate cores, which will require
	// to spawn threads etc. and provide different core masks.
	LOG("TODO: run dem");
	// Ask tyche to give us a dump of the state.
	asm volatile (
		"movq $0xa, %%rax\n\t"
		"vmcall\n\t"
		:
		:
		: "rax", "memory"
			);

	// Clean up everything once we've check the results are correct.
	if (sdk_delete_domain(ping) != SUCCESS) {
		ERROR("Unable to delete the enclave.");
		goto failure;
	}
	if (sdk_delete_domain(pong) != SUCCESS) {
		ERROR("Unable to delete pong.");
		goto failure;
	}
	return 0;
failure:
	return -1;
}
