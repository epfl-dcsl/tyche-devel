#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "common.h"
#include "common_log.h"
#include "ssl_redis_app.h"
#include "sdk_tyche.h"
#include "sdk_tyche_rt.h"
#include "contalloc_driver.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ucontext.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <ucontext.h>
#include <pthread.h>
#include <sched.h>

// ———————————————————————— Declare the RB functions ———————————————————————— //

RB_DECLARE_FUNCS(char);

// —————————————————————————————— Local types ——————————————————————————————— //

typedef struct domain_args_t {
  /// The core for the domain.
  usize core;
  /// The domain we need to run.
  tyche_domain_t* domain;
  /// Just for debugging.
  two_way_channel_t* debug_chan;
  /// The role for the debug thread.
  int debug_role;
} domain_args_t;

typedef struct pipe_state_t {
  /// The memory fd for the memory allocation.
  int memfd;

  /// The domain that holds the pipes.
  tyche_domain_t* pipe_holder;
} pipe_state_t;

// ————————————————————————————— Local globals —————————————————————————————— //

pipe_state_t* pipes = NULL;

char * domain_names[NB_DOMAINS]  = {
  "SSL",
  "REDIS",
};

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

int pin_self_to_core(usize core) {
  pthread_t thread = pthread_self();
  cpu_set_t affinity_mask;
  CPU_ZERO(&affinity_mask);
  CPU_SET(core, &affinity_mask);
  if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &affinity_mask) != 0) {
    ERROR("Unable to set thread affinity on core %lld", core);
    return FAILURE;
  }
  return SUCCESS;
}

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
    // Memset the pipe region.
    memset((void*) (slot->virtoffset), 0, slot->size);
    // We expect only one pipe so let's init is as the redis channel.
    redis_channel_t* redis_chan = (redis_channel_t*) slot->virtoffset;
    if (rb_char_init(&(redis_chan->request), MSG_BUFFER_SIZE,
            (char*)(REDIS_PIPE_ADDRESS + offsetof(redis_channel_t, request_buffer))) != SUCCESS) {
      ERROR("Unable to initialize the redis request channel.");
      exit(-1);
    }
    if (rb_char_init(&(redis_chan->response), MSG_BUFFER_SIZE,
            (char*)(REDIS_PIPE_ADDRESS + offsetof(redis_channel_t, response_buffer))) != SUCCESS) {
      ERROR("Unable to initialize the redis response channel.");
      exit(-1);
    }

    // Get the physoffset.
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


// ———————————————————————————— Running domains ————————————————————————————— //

// Thread running redis.
void* run_domain(void* arg) {
  domain_args_t* args = (domain_args_t*) arg;
  if (pin_self_to_core(args->core) != SUCCESS) {
      ERROR("Failed to pin thread to core %lld.", args->core);
      goto failure;
  }
  LOG("About to run dom %s on core %lld", domain_names[args->debug_role], args->core);
  // Run the domain.
  if (sdk_call_domain(args->domain) != SUCCESS) {
    ERROR("Failed to run domain %lld", args->core);
    goto failure;
  }
  LOG("The %s domain exited!", domain_names[args->debug_role]);
  exit(-1);
  return NULL;
failure:
  return NULL;
}

// ———————————————————————————— Helper functions ———————————————————————————— //


// This returns the mask of the domains_cores, not the core id.
// For the untrusted core, it is the core id.
// For the core id, do a -1.
static int core_allocation(usize *untrusted_core, usize domains_core[NB_DOMAINS]) {
  usize core_count = 0;
  if (untrusted_core == NULL || domains_core == NULL) {
    goto failure;
  }
  core_count = sdk_get_core_count();
  // the SDK-Tyche requires 3 cores: 1) untrusted, 2) ssl, 3) redis.
  // Avoid running thread benchmarks with sdktyche that does not have interrupts.
#if !defined(RUN_WITH_KVM) || RUN_WITH_KVM == 0
  if (core_count < 3) {
    ERROR("The # of cores (%lld) must be > 2 for tyche sdk", core_count);
    goto failure;
  }
#endif
  *untrusted_core = 0;
  if (core_count == 1) {
    domains_core[SSL_DOMAIN] = 1 << 0;
    domains_core[REDIS_DOMAIN] = 1 << 0;
  } else if (core_count == 2) {
    domains_core[SSL_DOMAIN] = 1 << 0;
    domains_core[REDIS_DOMAIN] = 1 << 1;
  } else {
    domains_core[SSL_DOMAIN] = 1 << 1;
    domains_core[REDIS_DOMAIN] = 1 << 2;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

static usize coremap_to_core(usize coremap) {
  for (usize i = 0; i < 32; i++) {
    if (((1ULL << i) & coremap) != 0) {
        return i;
    }
  }
  ERROR("Unable to find the core index in %llx", coremap);
  exit(-1);
  return 0;
}

// —————————————————————————————————— Main —————————————————————————————————— //
int main(int argc, char *argv[]) {
  // The domains.
  tyche_domain_t *domains[NB_DOMAINS] = {NULL, NULL};
  // The paths to the domain binaries.
  char* domains_paths[NB_DOMAINS] = {"ssl_enclave", "redis_enclave"};
  // The pthread handles for the domains.
  pthread_t domains_threads[NB_DOMAINS] = {0, 0};
  // The cores for the domains.
  usize domains_coremap[NB_DOMAINS] = {0, 0};
  // The domain args.
  domain_args_t domains_args[NB_DOMAINS];
  // Number of cores.
  usize core_count = sdk_get_core_count();
  // The output core
  usize untrusted_core = 0;
  // The sslyption channel.
  ssl_channel_t * ssl_comm = NULL;

  // Do the core allocation.
  if (core_allocation(&untrusted_core, domains_coremap) != SUCCESS) {
    ERROR("Unable to perform the core allocation.");
    goto failure;
  }

  // Pin ourselves to the core untrusted core.
  if (pin_self_to_core(untrusted_core) != SUCCESS) {
    goto failure;
  }

  // Set the skd pipe handler.
  sdk_handle_pipes = handle_pipes;

  // Allocate & load the domains.
  for (int i = 0; i < NB_DOMAINS; i++) {
    domains[i] = malloc(sizeof(tyche_domain_t));
    if (domains[i] == NULL) {
      ERROR("Unable to allocate domain %d", i);
      goto failure;
    }
    if (sdk_create_domain(domains[i], domains_paths[i], domains_coremap[i], 0,
          DEFAULT_PERM) != SUCCESS) {
      ERROR("Unable to load the domain %d", i);
      goto failure;
    }
  }

  // Initialize the communication channels.
  ssl_comm = (ssl_channel_t*) find_default_shared(domains[SSL_DOMAIN]);
  if (ssl_comm == NULL) {
    ERROR("Unable to find the default shared region in dom %d.", SSL_DOMAIN);
    goto failure;
  }
  // Initialize the channels.
  if (rb_char_init(&(ssl_comm->request), MSG_BUFFER_SIZE,
        ssl_comm->request_buffer) != SUCCESS) {
    ERROR("Problem in the init of the request channel.");
    goto failure;
  }
  if (rb_char_init(&(ssl_comm->response), MSG_BUFFER_SIZE,
        ssl_comm->response_buffer) != SUCCESS) {
    ERROR("Problem in the init of response channel.");
    goto failure;
  }
  memset(ssl_comm->request_buffer, 0, sizeof(char) * MSG_BUFFER_SIZE);
  memset(ssl_comm->response_buffer, 0, sizeof(char) * MSG_BUFFER_SIZE);
  
  // Run the domain threads.
  // TODO: we need some kind of synchronization to init the channel
  // between ssl and redis OR we make sure the pipe is mmaped to 0.
  for (int i = 0; i < NB_DOMAINS; i++) {
    // The domains_args should outlive the threads on this stack.
    domain_args_t* args = &domains_args[i];
    args->core = coremap_to_core(domains_coremap[i]);
    args->domain = domains[i];
    // Only used for debugging.
    args->debug_chan = ssl_comm;
    args->debug_role = i;
    if (pthread_create(&domains_threads[i], NULL, run_domain, (void*) args) < 0) {
      ERROR("Failed to run the domain %d thread.", i);
      goto failure;
    }
  }

  // run the tcp server.
  if (tcp_start_server(untrusted_core, ssl_comm) != SUCCESS) {
    ERROR("TCP server failed.");
    goto failure;
  }

  // Join the threads, not sure it's really needed.
  for (int i = 0; i < NB_DOMAINS; i++) {
    pthread_join(domains_threads[i], NULL);
  }

  // Delete the domains, that as well might never be executed.
  for (int i = 0; i < NB_DOMAINS; i++) {
    if (sdk_delete_domain(domains[i]) != SUCCESS) {
      ERROR("Unable to delete the domain %d.", i);
      goto failure;
    }
  }
  return SUCCESS;
failure:
  return FAILURE;
}
