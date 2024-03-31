#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>

#include "common_log.h"
#include "sdk_tyche.h"

// ————————————————————————————————— Hooks —————————————————————————————————— //
int (*sdk_handle_pipes)(tyche_domain_t*) = NULL;

// ———————————————————————————— Helper functions ———————————————————————————— //
int sdk_get_core_count(void) { return sysconf(_SC_NPROCESSORS_ONLN); }

usize sdk_all_cores_mask(void) {
  int cores = sdk_get_core_count();
  usize mask = 0;
  if (cores <= 0) {
    return 0;
  }
  for (int i = 0; i < cores; i++) {
    mask = (mask << 1) | 1;
  }
  return mask;
}

usize sdk_pin_to_current_core(void) {
  // Figure out sched-affinity.
  pthread_t thread;
  thread = pthread_self();
  cpu_set_t affinity_mask;
  int local_cpu_id = sched_getcpu();
  CPU_ZERO(&affinity_mask);
  CPU_SET(local_cpu_id, &affinity_mask);

  if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &affinity_mask) != 0) {
    ERROR("Unable to set thread affinity.");
    exit(-1);
  }
  return (1UL << local_cpu_id);
}
