#pragma once

#include <stdbool.h>
#include <stddef.h>

// ————————————————————————— Environment Variables —————————————————————————— //
#define NB_ENV_VARS (8)
#define RUN_CREATE_DELETE "RUN_CREATE"
#define RUN_TRANSITION "RUN_TRANSITION"
#define RUN_ATTESTATION "RUN_ATTESTION"
#define RUN_ENCLAVES "RUN_ENCLAVES"
#define RUN_SANDBOXES "RUN_SANDBOXES"
#define RUN_MIN "RUN_MIN"
#define RUN_MAX "RUN_MAX"
#define RUN_NB_ITER "RUN_NB_ITER"

// ———————————————————————————— Global variables ———————————————————————————— //
extern const char* domain_size_names[7];

// ————————————————————————————————— Types —————————————————————————————————— //

/// The available sizes for the benchmarks.
typedef enum domain_size_t {
	S_8k = 0,
	S_12k = 1,
	S_128k = 2,
	S_256k = 3,
	S_512k = 4,
	S_1M = 5,
	S_10M = 6,
} domain_size_t;

/// The configuration for the benchmark.
typedef struct ubench_config_t {
	/// Run create delete ubench
	bool run_create_delete;
	/// Run transition ubench
	bool run_transition;
	/// Run attestation ubench
	bool run_attestation;
	/// Run sandboxes
	bool run_sandboxes;
	/// Run enclaves
	bool run_enclaves;
	/// Minimal size of enclave in pages;
	domain_size_t min;
	/// Maximal size of enclave in pages;
	domain_size_t max;
	/// Iterations per operation measured.
	size_t nb_iterations;
} ubench_config_t;
