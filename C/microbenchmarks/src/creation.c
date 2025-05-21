#include "display.h"
#include "measurement.h"
#include "ubench.h"
#include "common.h"
#include "sdk_tyche.h"
#include "backend.h"
#include "tyche_api.h"
#include <sys/mman.h>
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>


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

static void creation_alternative(tyche_domain_t* domain, size_t size, bool hash, segment_type_t confidential);


static void run_creation_iteration2(char* name, size_t iter, size_t size, bool hash, segment_type_t confidential) {
  assert(iter > 0);
  time_measurement_t start;
  time_measurement_t end;
  time_diff_t creation = 0;
  time_diff_t deletion = 0;
  void* comparable_region = NULL;
  tyche_domain_t* domains = calloc(iter, sizeof(tyche_domain_t));
  assert(domains != NULL);
  memset(domains, 0, iter * sizeof(tyche_domain_t));
  
  // Map the region in case we need it.
  comparable_region = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_POPULATE|MAP_ANONYMOUS, -1, 0);
  if (comparable_region == MAP_FAILED) {
    perror("mmap");
    abort();
  }
  memset(comparable_region, 0, size);

  // Creation
  assert(take_time(&start));
  for (int i = 0; i < iter; i++) {
    creation_alternative(&domains[i], size, hash, confidential);
  }
  assert(take_time(&end));
  creation = compute_elapsed(&start, &end);

  // Deletion
  assert(take_time(&start));
  for (int i = 0; i < iter; i++) {
    assert(backend_td_delete(&domains[i]) == SUCCESS);
    if (hash) {
      memset(comparable_region, 0, size);
    }
  }
  assert(take_time(&end));
  deletion = compute_elapsed(&start, &end);
  munmap(comparable_region, size);

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

#define CREATION2 1

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

#ifndef CREATION2
    for (int j = 0; j < bench->outer; j++) {
      run_creation_iteration(name, bench->inner);
    }
#else 
  bool hash = false;
  segment_type_t conf_shared = SHARED;
  size_t size = domain_sizes[i];
  
  if (strstr(name, "carve")) {
    conf_shared = CONFIDENTIAL;
  } else if (strstr(name, "enclave")) {
    conf_shared = CONFIDENTIAL;
    hash = true;
  }

  for (int j = 0; j < bench->outer; j++) {
    run_creation_iteration2(name, bench->inner, size, hash, conf_shared);
  }

#endif
    free(name);
  }
}

static void sha256(const void *data, size_t len, unsigned char output[SHA256_DIGEST_LENGTH]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(output, &ctx);
}

static void creation_alternative(tyche_domain_t* domain, size_t size, bool hash, segment_type_t confidential) {
  domain_mslot_t *slot = NULL;
  unsigned char output[SHA256_DIGEST_LENGTH];
  domain->core_map = 1;
  if (backend_td_create(domain) != SUCCESS) {
    abort();
  }

  if (backend_td_mmap(domain, 0, size, PROT_READ|PROT_WRITE, 0) != SUCCESS) {
    abort();
  }
  dll_foreach(&(domain->mmaps), slot, list) {
    if (hash) {
      sha256((void*) (slot->virtoffset), slot->size, output);
    }
    memory_access_right_t flags = MEM_READ;
    if (confidential) {
      flags |= MEM_CONFIDENTIAL;
    }
    if (backend_td_register_region(domain, slot->virtoffset, slot->size,
          flags, confidential) != SUCCESS) {
      abort(); 
    }
  }

 // Set the traps.
  for (usize i = TYCHE_CONFIG_TRAPS; i <= TYCHE_CONFIG_TRAPS3; i++) {
    int idx = (int)(i - TYCHE_CONFIG_TRAPS);
    if (backend_td_config(
        domain, i, NO_TRAPS[idx]) != SUCCESS) {
      abort();
    }
  }

  // Set the cores. 
  if (backend_td_config(
        domain, TYCHE_CONFIG_CORES, 1) != SUCCESS) {
    abort();
  }
  // Set the domain permissions.
  if (backend_td_config(
        domain, TYCHE_CONFIG_PERMISSIONS, DEFAULT_PERM) != SUCCESS) {
    abort();
  }

  // Do the default configuration for mgmt.
  for (unsigned int p = TYCHE_CONFIG_R16; p < TYCHE_NR_CONFIGS; p++) {
    if (backend_td_config(domain, p, ~((usize) 0)) != SUCCESS) {
      abort();
    }
  }

  // Create the core
  if (backend_td_create_vcpu(domain, 0) != SUCCESS) {
      abort();
  }
  if (backend_td_init_vcpu(domain, 0) != SUCCESS) {
      abort();
  }
  // Commit the domain.
  if (backend_td_commit(domain)!= SUCCESS) {
    abort();
  }
}
