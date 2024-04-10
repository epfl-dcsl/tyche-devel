#include "display.h"
#include "measurement.h"
#include "ubench.h"
#include "common.h"
#include "sdk_tyche.h"
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static void display_creation_header(char* prefix, ubench_config_t* bench) {
  assert(prefix != NULL && bench != NULL);
  printf("Creation[%s -> %s] run on %s showing %ld (outer) averages of %ld (inner) create/delete\n",
      domain_size_names[bench->min_size],
      domain_size_names[bench->max_size], prefix, bench->outer, bench->inner);
  char** cols = allocate_buffer();
  assert(cols != NULL);
  sprintf(cols[0], "name[iter #]");
  sprintf(cols[1], "creation (%s)", TIME_MEASUREMENT_UNIT); 
  sprintf(cols[2], "deletion (%s)", TIME_MEASUREMENT_UNIT);
  print_line(cols, 3);
  free_buffer(cols);
}

static void run_creation_iteration(char* name, size_t iter) {
  assert(name != NULL && iter > 0);
  time_measurement_t start;
  time_measurement_t end;
  time_diff_t creation = 0;
  time_diff_t deletion = 0;
  tyche_domain_t* domains = calloc(iter, sizeof(tyche_domain_t));
  assert(domains != NULL);
  memset(domains, 0, iter * sizeof(tyche_domain_t));

  // Creation
  assert(take_time(&start));
  for (int i = 0; i < iter; i++) {
    if (sdk_create_domain(&domains[i], name, 1, NO_TRAPS, DEFAULT_PERM) != SUCCESS) {
      abort();
    }
  }
  assert(take_time(&end));
  creation = compute_elapsed(&start, &end);

  // Deletion
  assert(take_time(&start));
  for (int i = 0; i < iter; i++) {
    assert(sdk_delete_domain(&domains[i]) == SUCCESS);
  }
  assert(take_time(&end));
  deletion = compute_elapsed(&start, &end);

  // Display the result.
  char** cols = allocate_buffer(); 
  assert(cols != NULL);
  sprintf(cols[0], "%s", name);
  sprintf(cols[1], "%.3f", creation / ((double)iter));
  sprintf(cols[2], "%.3f", deletion / ((double)iter));
  print_line(cols, 3);

  // Cleanup
  free(domains);
  free_buffer(cols);
}

void run_creation(char* prefix, ubench_config_t* bench) {
  assert(prefix != NULL && bench != NULL);

  // print header.
  display_creation_header(prefix, bench);
  // Run the benchmark for each selected size.
  for (domain_size_t i = bench->min_size; i <= bench->max_size; i++) {
    // We have our two loops.
    char* name = malloc(100 * sizeof(char));
    assert(name != NULL);
    sprintf(name, "%s/%s", prefix, domain_size_names[i]);
    for (int j = 0; j < bench->outer; j++) {
      run_creation_iteration(name, bench->inner);
    }
    free(name);
  }
}
