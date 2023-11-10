#include "display.h"
#include "ubench.h"
#include "measurement.h"
#include "common.h"
#include "sdk_tyche.h"
#include "sdk_tyche_rt.h"
#include "tyche_api.h"
#include "ecs.h"
#include "tyche_driver.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// ——————————————————————————— Display functions ———————————————————————————— //

static void display_transition_header(char* prefix, ubench_config_t* bench) {
  assert(prefix != NULL && bench != NULL);
#ifdef RUN_WITH_KVM
    char* sdk = "sdk-kvm";
#else
    char* sdk = "sdk-tyche";
#endif
  printf("Transition for %s showing %ld (outer) averages of %ld (inner) w/ %s\n",
      prefix, bench->outer, bench->inner, sdk);
  ;
  char** cols = allocate_buffer();
  sprintf(cols[0], "call %s (%s)", sdk, TIME_MEASUREMENT_UNIT);
  sprintf(cols[1], "call raw (%s)", TIME_MEASUREMENT_UNIT);
  print_line(cols, 2);
  free_buffer(cols);
}

static void display_transition_results(time_diff_t* sdk, time_diff_t* raw, size_t len) {
  assert(sdk != NULL && raw != NULL && len > 0);
  char** cols = allocate_buffer();
  for (int i = 0; i < len; i++) {
    sprintf(cols[0], "%.3f", sdk[i]);
#ifdef RUN_WITH_KVM
    sprintf(cols[1], "NA");
#else
    sprintf(cols[1], "%.3f", raw[i]);
#endif
    print_line(cols, 2);
  }
  free_buffer(cols);
}

// ———————————————————————————— Helper functions ———————————————————————————— //

static bool bench_find_switch(capa_index_t* res) {
  capa_index_t next = 0;
  assert(res != NULL);
  do {
    capability_t tmp_capa;
#if defined(CONFIG_RISCV) || defined(__riscv)
    if (user_enumerate_capa(next, &next, &tmp_capa) != SUCCESS || next == 0) {
#else 
    if (enumerate_capa(next, &next, &tmp_capa) != SUCCESS || next == 0) { 
#endif
        goto failure;
    }
    /// We found it.
    if (tmp_capa.capa_type == Switch) {
      *res = tmp_capa.local_id;
      return true;
    }
  } while (next != 0);
failure:
  // Something went wrong.
  return false;
}

// ——————————————————————————————— Benchmark ———————————————————————————————— //

void run_transition(char* prefix, ubench_config_t *bench) {
  tyche_domain_t domain;
  char name[100] = {0};
  capa_index_t capa_switch = 0;
  usize core_mask = sdk_pin_to_current_core();
  assert(prefix != NULL && bench != NULL);
  time_diff_t* sdk_times = calloc(bench->outer, sizeof(time_diff_t));
  time_diff_t* raw_times = calloc(bench->outer, sizeof(time_diff_t));
  memset(sdk_times, 0, bench->outer * sizeof(time_diff_t));
  memset(raw_times, 0, bench->outer * sizeof(time_diff_t));

  display_transition_header(prefix, bench);

  // Create the domain.
  sprintf(name, "%s/transition", prefix);
  //printf("\nCreating domain...\n"); 
  assert(sdk_create_domain(&domain, name, core_mask, ALL_TRAPS, DEFAULT_PERM) == SUCCESS);

  // Warmup transition.
  //printf("\nCalling domain...\n");
  assert(sdk_call_domain(&domain) == SUCCESS);

  //printf("\nAttempt to find switch capa domain...\n");
  assert(bench_find_switch(&capa_switch));

  //printf("\nFound the switch capa...\n");

  // Let's go for the sdk benchmark.
  for (int i = 0; i < bench->outer; i++) {
    time_measurement_t start = {0};
    time_measurement_t end = {0};

    assert(take_time(&start));
    for (int j = 0; j < bench->inner; j++) {
      assert(sdk_call_domain(&domain) == SUCCESS);
    }
    assert(take_time(&end));

    sdk_times[i] = (compute_elapsed(&start, &end))/((double)bench->inner);

#ifndef RUN_WITH_KVM
  // Do the same with a raw call.
    assert(take_time(&start));
    for (int j = 0; j < bench->inner; j++) {
      // A raw syscall.
#if defined(CONFIG_RISCV) || defined(__riscv)
        asm volatile(
            "mv a0, %0\n\t"
            "mv a1, %1\n\t"
            "li a7, 0x5479636865\n\t"
            "mret\n\t"
            :
            : "rm" ((usize)TYCHE_SWITCH), "rm" (capa_switch)
            : "a0", "a1", "a7", "memory");
#else
      asm volatile(
          "movq %0, %%rdi\n\t"
          "movq %1, %%rax\n\t"
          "vmcall\n\t"
          :
          : "rm" (capa_switch), "rm" ((usize)TYCHE_SWITCH)
          : "rax", "rdi", "memory");
#endif
    }
    assert(take_time(&end));
    raw_times[i] = (compute_elapsed(&start, &end))/((double)bench->inner);
#endif
  }
  // Clean up the domain.
  assert(sdk_delete_domain(&domain) == SUCCESS);
  
  // Display the results.
  display_transition_results(sdk_times, raw_times, bench->outer);
}
