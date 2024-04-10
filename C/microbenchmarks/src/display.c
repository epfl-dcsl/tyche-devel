#include "display.h"
#include "ubench.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void print_line(char** cols, size_t len) {
  int pad = 0;
  assert(cols != NULL);
  for (int i = 0; i < len; i++) {
    assert(cols[i] != NULL);
    size_t slen = strlen(cols[i]);
    if (slen < COL_WIDTH) {
      printf("%s", cols[i]);
    } else {
      printf("%.15s...", cols[i]);
    }
    pad = COL_WIDTH - strlen(cols[i]);
    for (int j = 0; j < pad; j++) {
      putchar(' ');
    }
  }
  putchar('\n');
}

void display_config(ubench_config_t *bench) {
  assert(bench != NULL);
  printf("Selected benchmarks:");
  if (bench->creation) {
    printf(" creation");
  }
  if (bench->transition) {
    printf(" transition");
  }
  if (bench->attestation) {
    printf(" attestation");
  }
  if (!bench->creation && !bench->transition && !bench->attestation) {
    printf(" YOU HAVE NOT SELECTED ANY BENCHMARK");
  } 
  printf("\n");
  if (bench->attestation || bench->creation) {
    printf("Selected sizes: [");
    for (domain_size_t i = bench->min_size; i <= bench->max_size; i++) {
      printf(" %s", domain_size_names[i]);
    }
    printf(" ]\n");
  }
  printf("Selected workloads: ");
  if (bench->enclaves) {
    printf(" enclaves");
  }
  if (bench->sandboxes) {
    printf(" sandboxes");
  }
  if (bench->carves) {
    printf(" carves");
  }
  printf("\n");
  printf("Running %ld (outer) times %ld (inner) repetitions/run\n", bench->outer, bench->inner);
}


char** allocate_buffer(void) {
  char** buff = calloc(MAX_NB_COLS, sizeof(char*));
  assert(buff != NULL);
  for (int i = 0; i < MAX_NB_COLS; i++) {
    buff[i] = malloc(sizeof(char) * DISP_INPUT);
    assert(buff[i] != NULL);
    memset(buff[i], 0, DISP_INPUT * sizeof(char));
  }
  return buff;
}

void free_buffer(char** buf) {
  assert(buf != NULL);
  for (int i = 0; i < MAX_NB_COLS; i++) {
    assert(buf[i] != NULL);
    free(buf[i]);
  }
  free(buf);
}

