#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "display.h"
#include "ubench.h"
#include "environment.h"
#include "measurement.h"
#include "benchmarks.h"
// ———————————————————————————————— Globals ————————————————————————————————— //

#define NB_WORKLOADS 3
#define NB_BENCHMARKS 4

static const domain_size_t default_min_size = S_8k;
static const domain_size_t default_max_size = S_1M;
static const size_t defautl_inner = 1;
static const size_t default_outer = 1;

/// The names for the benchmarks sizes.
const char* domain_size_names[S_Max] = {
  "8k",
  "16k",
  "32k",
  "64k",
  "128k",
  "256k",
  "512k",
  "1M",
  "1G",
};

const size_t domain_sizes[S_Max] = {
    8 * 1024,             // 8k
    16 * 1024,            // 16k
    32 * 1024,            // 32k
    64 * 1024,            // 64k
    128 * 1024,           // 128k
    256 * 1024,           // 256k
    512 * 1024,           // 512k
    1024 * 1024,          // 1M
    1024L * 1024 * 1024,  // 1G
};

/// The default benchmark configuration.
static ubench_config_t bench = {
  .creation = false,
  .transition = false,
  .attestation = false,
  .enclaves = false,
  .sandboxes = false,
  .carves = false,
  .min_size = default_min_size,
  .max_size = default_max_size,
  .inner = defautl_inner,
  .outer = default_outer,
};

// ———————————————————————————— Local functions ————————————————————————————— //

static bool check_configuration(ubench_config_t* bench) {
  if (bench == NULL) {
    goto failure;
  }
  if (bench->min_size > bench->max_size) {
    goto failure;
  }
  if (bench->inner <= 0) {
    goto failure;
  }
  if (bench->outer <= 0) {
    goto failure;
  }
  return true;
failure:
  return false;
}

// ————————————————————————————— Main function —————————————————————————————— //
int main(void) {
  bool workloads[NB_WORKLOADS] = {false};
  char* workload_prefixes[NB_WORKLOADS] = {
    "bin/enclaves/",
    "bin/sandboxes/",
    "bin/carve/",
  };

  bool benchmarks[NB_BENCHMARKS] = {false};
  bench_f run_bench[NB_BENCHMARKS] = {
    run_creation,
    run_transition,
    run_attestation,
    run_hwcomm,
  };

  // Parse the benchmark configuration.
  parse_configuration(&bench);
  // Check that the configuration is correct.
  assert(check_configuration(&bench));
  // Print the configuration.
  display_config(&bench);

  // Get the configuration for the workloads.
  workloads[0] = bench.enclaves;
  workloads[1] = bench.sandboxes;
  workloads[2] = bench.carves;

  // Get the configuration for the benchmarks.
  benchmarks[0] = bench.creation;
  benchmarks[1] = bench.transition;
  benchmarks[2] = bench.attestation;
  benchmarks[3] = bench.hwcomm;

  // Run the benchmarks.
  for (int i = 0; i < NB_BENCHMARKS; i++) {
    if (benchmarks[i] == false) {
      continue;
    }
    // Special case for hardware measurement.
    if (run_bench[i] == run_hwcomm) {
      run_bench[i](NULL, &bench);
    }
    for (int j = 0; j < NB_WORKLOADS; j++) {
      if (workloads[j] == false) {
        continue;
      }
      run_bench[i](workload_prefixes[j], &bench);
    }
  }
  printf("All done!\n");
  return 0;
}
