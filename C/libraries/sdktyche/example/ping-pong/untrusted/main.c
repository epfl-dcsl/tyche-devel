#include <string.h>
#define _GNU_SOURCE
#include "common.h"
#include "common_log.h"
#include "ping_pong.h"
#include "sdk_tyche.h"
#include "sdk_tyche_rt.h"
#include "tyche_capabilities_types.h"
#include "contalloc_driver.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

// —————————————————————————————— Local types ——————————————————————————————— //

typedef struct pipe_state_t {
	/// The memory fd for the memory allocation.
	int memfd;

	/// The domain that holds the pipes.
	tyche_domain_t* pipe_holder;
} pipe_state_t;

// ——————————————————————————————— Constants ———————————————————————————————— //

// Enclaves file names.
static const char* ping_name = "ping_enclave";
static const char* pong_name = "pong_enclave";

static const char* default_message =	"You spin me round round\n"
																			"Baby right round,\n"
																			"Like a record baby,\n"
																			"Round round\n";

pipe_state_t* pipes = NULL;

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

// —————————————————————— Function to handle the pipes —————————————————————— //

int handle_pipes(tyche_domain_t* domain) {
	domain_mslot_t *slot = NULL;
	domain_mslot_t *model = NULL;
	msg_t info = {0};
	if (pipes != NULL) {
		goto copy_pipe;
	}
	pipes = malloc(sizeof(pipe_state_t));
	if (pipes == NULL) {
		ERROR("Unable to allocate pipe state.");
		goto failure;
	}
	memset(pipes, 0, sizeof(pipe_state_t));
	pipes->memfd = open("/dev/contalloc", O_RDWR);
	if (pipes->memfd < 0) {
		ERROR("Unable to open contalloc driver.");
		goto failure;
	}
	// Allocate the pipes with contalloc.
	dll_foreach(&(domain->pipes), slot, list) {
		slot->virtoffset = (usize) mmap(NULL, (size_t) slot->size,
				PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, pipes->memfd, 0);
		if (((void*)(slot->virtoffset)) == MAP_FAILED) {
			ERROR("Unable to allocate pipe memory.");
			exit(-1);
		}
		if (ioctl(pipes->memfd, CONTALLOC_GET_PHYSOFFSET, &info) != SUCCESS) {
			ERROR("Unable to get the pyshoffset for the pipe");
			exit(-1);
		}
		slot->physoffset = info.physoffset;
		//Talk to the backend to register the pipe.
		//For the moment put default access rights instead of translating them
		//Let's ask for a width of 2 for now.
		if (sdk_create_pipe(domain, &(slot->id), slot->physoffset, slot->size,
					MEM_SUPER|MEM_WRITE|MEM_READ, 2) != SUCCESS) {
			ERROR("Unable to create the pipe");
			exit(-1);
		}
	}
	pipes->pipe_holder = domain;
	// Skip to acquire
	goto acquire_pipes;
copy_pipe:
	// We need to copy the pipes.
	slot = domain->pipes.head;
	model = pipes->pipe_holder->pipes.head;
	while (slot != NULL && model != NULL) {
		if (slot->size != model->size) {
			ERROR("Pipe sizes do not match.");
			exit(-1);
		}
		slot->virtoffset = model->virtoffset;
		slot->physoffset = model->physoffset;

		slot = slot->list.next;
		model = model->list.next;
	}
	if (slot != NULL || model != NULL) {
		ERROR("Number of slots for pipes do not match");
		exit(-1);
	}
	// Make the calls to acquire the pipes
acquire_pipes:
	slot = NULL;
	dll_foreach(&(domain->pipes), slot, list) {
		if (sdk_acquire_pipe(domain, slot) != SUCCESS) {
			ERROR("Acquire failed!");
			exit(-1);
		}
	}
	return SUCCESS;
failure:
	return FAILURE;
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

	// Setup the handler for the pipes.
	sdk_handle_pipes = handle_pipes;

	// Allocate ping and pong.
	ping = malloc(sizeof(tyche_domain_t));
	if (ping == NULL) {
		ERROR("Unable to allocate ping.");
		goto failure;
	}
	pong = malloc(sizeof(tyche_domain_t));
	if (pong == NULL) {
		ERROR("Unable to allocate pong.");
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
	// This could be hardcoded in ping.
	ping_info->channel = (void*) 0x301000;
	ping_info->msg_size = strlen(default_message) +1;
	memcpy(ping_info->msg_buffer, default_message, strlen(default_message) + 1);

	pong_info = (info_t*) find_default_shared(pong);
	if (pong_info == NULL) {
		ERROR("Unable to find the default shared region for pong");
		goto failure;
	}
	memset(pong_info, 0, sizeof(info_t));
	// This could be hardcoded in pong.
	pong_info->channel = (void*) 0x301000;
	pong_info->msg_size = strlen(default_message) + 1;

	// TODO: make the enclaves runs on separate cores, which will require
	// to spawn threads etc. and provide different core masks.
	// For a first version I should be able to just run ping first and then pong.
	LOG("calling ping");
	if (sdk_call_domain(ping) != SUCCESS) {
		ERROR("Failed to call ping.");
		goto failure;
	}
	if (ping_info->status != DONE_SUCCESS) {
		ERROR("Unexpected ping status: %d", ping_info->status);
		goto failure;
	}
	LOG("Calling pong");
	if (sdk_call_domain(pong) != SUCCESS) {
		ERROR("Failure to call pong");
		goto failure;
	}
	if (pong_info->status != DONE_SUCCESS)  {
		ERROR("Unexpected pong status: %d", pong_info->status);
		goto failure;
	}
	LOG("Done with pong, here is the message:\n%s", pong_info->msg_buffer);
	// Ask tyche to give us a dump of the state.
	/*asm volatile (
		"movq $0xa, %%rax\n\t"
		"vmcall\n\t"
		:
		:
		: "rax", "memory"
			);*/

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
