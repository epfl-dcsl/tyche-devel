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

static void display_attestation(char* prefix, ubench_config_t* bench, time_diff_t* results, usize *sizes) {
  char** buf = allocate_buffer();
  assert(buf != NULL);
  assert(prefix != NULL && results != NULL && sizes != NULL);
  // Print the header.
  printf("Attestation: %ld (outer) averages over %ld (inner) runs.\n", bench->outer, bench->inner);
  printf("%s{ ", prefix);
  for (int i = bench->min_size; i <= bench->max_size; i++) {
    printf("%s ", domain_size_names[i]);
  }
  printf("}\n");
  sprintf(buf[0], "%ld calls (%s)", bench->inner, TIME_MEASUREMENT_UNIT);
  sprintf(buf[1], "avg (%s)/call", TIME_MEASUREMENT_UNIT);
  sprintf(buf[2], "#bytes/call");
  print_line(buf, 3);
  for (int i = 0; i < bench->outer; i++) {
    sprintf(buf[0], "%.3f", results[i]);
    sprintf(buf[1], "%.3f", results[i] / ((double) bench->inner));
    sprintf(buf[2], "%lld", sizes[i]);
    print_line(buf, 3);
  }
  printf("\n");
  free_buffer(buf);
}

/// Buffer used in the attestation.
/// Not that it makes a massive difference, but let's align it.
static char attestation_buffer[4096] __attribute__((aligned(4096))) = {0};

void run_attestation(char* prefix, ubench_config_t* bench) {
  assert(prefix != NULL && bench != NULL);
  attest_buffer_t buff_info;
  time_diff_t* results = calloc(bench->outer, sizeof(time_diff_t));
  usize* sizes = calloc(bench->outer, sizeof(usize));
  assert(results != NULL && sizes != NULL);
  // Load the domains first.
#ifdef RUN_WITH_KVM
  fprintf(stderr, "YOU ARE RUNNING ATTESTION WITH KVM\nRegions are not transfered yet!\n");
  return;
#endif
  size_t nb_domains = bench->max_size - bench->min_size + 1;
  tyche_domain_t* domains = calloc(nb_domains, sizeof(tyche_domain_t));
  assert(domains != NULL);
  for (domain_size_t i = bench->min_size; i <= bench->max_size; i++) {
    char name[100] = {0};
    sprintf(name, "%s/%s", prefix, domain_size_names[i]);
    int idx = i - bench->min_size;
    assert(sdk_create_domain(&domains[idx], name, 1, NO_TRAPS, DEFAULT_PERM) == SUCCESS);
  }

  // Initialize the request buffer.
  buff_info.start = (unsigned long) &attestation_buffer[0];
  buff_info.size = 4096;
  buff_info.written = 0;

  // Now run the benchmark.
  for (int i = 0; i < bench->outer; i++) {
    time_measurement_t start;
    time_measurement_t end;
    assert(take_time(&start));
    for (int j = 0; j < bench->inner; j++) {
      assert(ioctl(domains[0].handle, TYCHE_GET_ATTESTATION, &buff_info) == SUCCESS);
      assert(buff_info.written > 0);
    }
    assert(take_time(&end));
    results[i] = compute_elapsed(&start, &end);
    sizes[i] = buff_info.written;
  }

  // Cleanup the domains.
  for (domain_size_t i = bench->min_size; i <= bench->max_size; i++) {
    int idx = i - bench->min_size;
    assert(sdk_delete_domain(&domains[idx]) == SUCCESS);
  }
  
  // Display the results.
  display_attestation(prefix, bench, results, sizes);
  // Display the attestation.
  printf("Sample attestation:\n");
  for (int i = 0; i < buff_info.written; i++) {
    putchar(attestation_buffer[i]);
  }
  printf("\n");
  free(results);
  free(sizes);
}
