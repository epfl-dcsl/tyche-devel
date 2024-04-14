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

static void display_hwcomm_header(char* prefix, ubench_config_t* bench) {
  assert(bench != NULL);
  printf("Hardware communication showing %ld (outer) averages of %ld (inner)\n",
      bench->outer, bench->inner);
  ;
  char** cols = allocate_buffer();
  sprintf(cols[0], "outer #");
  sprintf(cols[1], "call-return (%s)", TIME_MEASUREMENT_UNIT);
  print_line(cols, 2);
  free_buffer(cols);
}

static void display_hwcomm_results(time_diff_t* timings, size_t len) {
  assert(timings != NULL && len > 0);
  char** cols = allocate_buffer();
  for (int i = 0; i < len; i++) {
    sprintf(cols[0], "iter %d", i);
    sprintf(cols[1], "%.3f", timings[i]);
    print_line(cols, 2);
  }
  free_buffer(cols);
}

// ——————————————————————————————— Benchmark ———————————————————————————————— //

void run_hwcomm(char* prefix, ubench_config_t *bench) {
  assert(bench != NULL);
  time_diff_t* timings = calloc(bench->outer, sizeof(time_diff_t));
  memset(timings, 0, bench->outer * sizeof(time_diff_t));

  display_hwcomm_header(prefix, bench);

  // Let's go for the sdk benchmark.
  for (int i = 0; i < bench->outer; i++) {
    time_measurement_t start = {0};
    time_measurement_t end = {0};

    assert(take_time(&start));
    for (int j = 0; j < bench->inner; j++) {


#if defined(CONFIG_RISCV) || defined(__riscv)
    asm volatile(
        "mv a0, %0\n\t"
        "li a7, 0x5479636865\n\t"
        "ecall\n\t"
        :
        : "rm" ((usize)TYCHE_TEST_CALL)
        : "a0", "a1", "memory");
#else
      // A raw syscall.
      asm volatile(
          "movq %0, %%rax\n\t"
          "vmcall\n\t"
          :
          : "rm" ((usize) TYCHE_TEST_CALL)
          : "rax", "memory");
#endif
    }
    assert(take_time(&end));
    timings[i] = (compute_elapsed(&start, &end))/((double)bench->inner);
  }
  // Clean up the domain.
  
  // Display the results.
  display_hwcomm_results(timings, bench->outer);
}
