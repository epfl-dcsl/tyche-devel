#pragma once

#include <stdbool.h>
#include <stddef.h>

// ————————————————————————— Environment Variables —————————————————————————— //
#define NB_ENV_VARS (10)
/// Benchmarks
#define CREATION "CREATION"
#define TRANSITION "TRANSITION"
#define ATTESTATION "ATTESTATION"
/// Workloads
#define ENCLAVES "ENCLAVES"
#define SANDBOXES "SANDBOXES"
#define CARVES "CARVES"
/// Configuration parameters
#define MIN_SIZE "MIN_SIZE"
#define MAX_SIZE "MAX_SIZE"
#define INNER "INNER"
#define OUTER "OUTER"

// ————————————————————————————————— Types —————————————————————————————————— //

/// The available sizes for the benchmarks.
typedef enum domain_size_t {
  S_8k = 0,
  S_16k = 1,
  S_32k = 2,
  S_64k = 3,
  S_128k = 4,
  S_256k = 5,
  S_512k = 6,
  S_1M = 7,
  S_Max = 8,
} domain_size_t;

/// Names for the domains.
extern const char* domain_size_names[S_Max];

/// The configuration for the benchmark.
typedef struct ubench_config_t {
  /// Run create delete ubench
  bool creation;
  /// Run transition ubench
  bool transition;
  /// Run attestation ubench
  bool attestation;
  /// Run enclaves
  bool enclaves;
  /// Run sandboxes
  bool sandboxes;
  /// Run carves
  bool carves;
  /// Minimal size of enclave in pages;
  domain_size_t min_size;
  /// Maximal size of enclave in pages;
  domain_size_t max_size;
  /// Inner loop value
  size_t inner;
  /// Outer loop value.
  size_t outer;
} ubench_config_t;
