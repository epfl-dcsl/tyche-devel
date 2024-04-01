#include <string.h>
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
#include <pthread.h>
#include <sched.h>

// —————————————————————————————— Local types ——————————————————————————————— //

typedef struct pipe_state_t {
	/// The memory fd for the memory allocation.
	int memfd;

	/// The domain that holds the pipes.
	tyche_domain_t* pipe_holder;
} pipe_state_t;

typedef struct ping_pong_args_t {
	/// The core on which we want the thread to execute.
	usize core;
	/// The enclave that needs to be executed.
	tyche_domain_t* domain;
} ping_pong_args_t;

// ——————————————————————————————— Constants ———————————————————————————————— //

// Enclaves file names.
static const char* ping_name = "ping_enclave";
static const char* pong_name = "pong_enclave";

static const char* default_message =	"You spin me round round\n"
																			"Baby right round,\n"
																			"Like a record baby,\n"
																			"Round round\n";
static const char* pong_placeholder = "You should not see this\n";

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

void* run_domain(void* args) {
	ping_pong_args_t* config = (ping_pong_args_t*) args;
	pthread_t thread = pthread_self();
	cpu_set_t affinity_mask;
	if (args == NULL) {
		ERROR("received a null argument in the run domain thread.");
		return NULL;
	}
	CPU_ZERO(&affinity_mask);
	// Trick to convert core mask into an id number.
	CPU_SET((config->core >> 1), &affinity_mask);
	if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &affinity_mask) != 0) {
		ERROR("Unable to set thread affinity on core %lld", config->core);
		return NULL;
	}
	// Now finally call the domain.
	if (sdk_call_domain(config->domain) != SUCCESS) {
		ERROR("Error running the domain on core %lld", config->core);
		return NULL;
	}
	return NULL;
}

int main(int argc, char *argv[]) {
	tyche_domain_t* ping = NULL;
	tyche_domain_t* pong = NULL;
	info_t* ping_info = NULL;
	info_t* pong_info = NULL;
	pthread_t threads[2] = {0};
	ping_pong_args_t args[2] = {0};

	// Parse the core configuration.
	// If we run with SDK_TYCHE, i.e., KVM=0, we need at least two cores.
	// With KVM, we can probably get away with 1 core.
	usize core_count = sdk_get_core_count();
	usize core_mask = sdk_all_cores_mask();
	usize ping_core = 1;
	usize pong_core = (core_count > 1)? 2 : 1;
#if !defined(RUN_WITH_KVM) || RUN_WITH_KVM == 0
	if (core_count <= 1) {
		ERROR("The # of cores (%lld) is insufficent to run this benchmark with tyche sdk.", core_count);
		exit(-1);
	}
#endif

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
	if (sdk_create_domain(ping, ping_name, ping_core, ALL_TRAPS,
				DEFAULT_PERM) != SUCCESS) {
		ERROR("Unable to parse the ping enclave.");
		goto failure;
	}
	if (sdk_create_domain(pong, pong_name, pong_core, ALL_TRAPS,
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
	memcpy(pong_info->msg_buffer, pong_placeholder, strlen(pong_placeholder) +1);
	// This could be hardcoded in pong.
	pong_info->channel = (void*) 0x301000;
	pong_info->msg_size = strlen(default_message) + 1;


	// Create the ping thread.
	args[0].core = ping_core;
	args[0].domain = ping;
	if (pthread_create(&threads[0], NULL, run_domain, (void*)(&args[0])) < 0) {
		ERROR("Failed to create ping thread.");
		goto failure;
	}

	// Create the pong thread.
	args[1].core = pong_core;
	args[1].domain = pong;
	if (pthread_create(&threads[1], NULL, run_domain, (void*)(&args[1])) < 0) {
		ERROR("Failed to create pong thread.");
		goto failure;
	}

	// Join on the threads.
	pthread_join(threads[0], NULL);
	pthread_join(threads[1], NULL);

	// Check the status.
	if (ping_info->status != DONE_SUCCESS) {
		ERROR("The ping status is not success: %d", ping_info->status);
		goto failure;
	}
	if (pong_info->status != DONE_SUCCESS) {
		ERROR("The pong status is not success: %d", pong_info->status);
	}
	// Check we received the correct message.
	if (strncmp(pong_info->msg_buffer, default_message, strlen(default_message)) != 0) {
		ERROR("The messages do not match!");
		goto failure;
	}
	LOG("The message we received: %s", pong_info->msg_buffer);

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
