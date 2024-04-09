#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ubench.h"
#include "environment.h"
#include "measurement.h"
#include "internal.h"

// ———————————————————————————————— Globals ————————————————————————————————— //

static const domain_size_t default_min_size = S_8k;
static const domain_size_t default_max_size = S_10M;
static const size_t default_nb_iterations = 10;
static const size_t default_rep_iter = 1;

/// The names for the benchmarks sizes.
const char* domain_size_names[7] = {
	"8k",
	"12k",
	"128k",
	"256k",
	"512k",
	"1M",
	"10M",
};

/// The default benchmark configuration.
static ubench_config_t bench = {
	.run_create_delete = false,
	.run_transition = false,
	.run_attestation = false,
	.run_sandboxes = false,
	.run_enclaves = false,
	.run_carves = false,
	.min = default_min_size,
	.max = default_max_size,
	.nb_iterations = default_nb_iterations,
	.rep_iter = default_rep_iter,
};

/// Prefixes where to find sandboxes and enclaves binaries.
static const char* sandbox_prefix = "bin/sandboxes/";
static const char* enclave_prefix = "bin/enclaves/";
static const char* carve_prefix = "bin/carve/";

// ———————————————————————————— Local functions ————————————————————————————— //

static bool check_configuration(ubench_config_t* bench) {
	if (bench == NULL) {
		goto failure;
	}
	if (bench->min > bench->max) {
		goto failure;
	}
	if (bench->nb_iterations <= 0) {
		goto failure;
	}
	if (bench->rep_iter <= 0) {
		goto failure;
	}
	return true;
failure:
	return false;
}

static void proxy_create_delete_bench(ubench_config_t* bench) {
	assert(bench != NULL);
	// Allocate the arrays for results.	
	time_diff_t* create_res = NULL; 
	time_diff_t* delete_res = NULL; 

	// Compute how many time slots we need.
	size_t nb_results = bench->max - bench->min + 1;
	create_res = calloc(nb_results, sizeof(time_diff_t));
	assert(create_res != NULL);
	memset(create_res, 0, nb_results * sizeof(time_diff_t));
	delete_res = calloc(nb_results, sizeof(time_diff_t));
	assert(delete_res != NULL);
	memset(delete_res, 0, nb_results * sizeof(time_diff_t));

	// Run sandboxes.
	// Run_internal checks what needs to be measured (create and or delete).
	if (bench->run_sandboxes) {
		assert(run_create_delete(sandbox_prefix, bench, create_res, delete_res, nb_results));
		display_create_delete(sandbox_prefix, bench, create_res, delete_res);
		memset(create_res, 0, nb_results * sizeof(time_diff_t));
		memset(delete_res, 0, nb_results * sizeof(time_diff_t));
	}

	// Run enclaves.
	if (bench->run_enclaves) {
		assert(run_create_delete(enclave_prefix, bench, create_res, delete_res, nb_results));
		display_create_delete(enclave_prefix, bench, create_res, delete_res);
		memset(create_res, 0, nb_results * sizeof(time_diff_t));
		memset(delete_res, 0, nb_results * sizeof(time_diff_t));
	}
	// Run carves.
	if (bench->run_carves) {
		assert(run_create_delete(carve_prefix, bench, create_res, delete_res, nb_results));
		display_create_delete(carve_prefix, bench, create_res, delete_res);
		memset(create_res, 0, nb_results * sizeof(time_diff_t));
		memset(delete_res, 0, nb_results * sizeof(time_diff_t));
	}
	// Free the results.
	free(create_res);
	free(delete_res);
}

static void proxy_transition_bench(ubench_config_t *bench) {
	time_diff_t* results = NULL;
	time_diff_t* raws = NULL;
	assert(bench != NULL);
	results = calloc(bench->rep_iter, sizeof(time_diff_t));
	raws = calloc(bench->rep_iter, sizeof(time_diff_t));
	assert(results != NULL && raws != NULL);
	memset(results, 0, bench->rep_iter * sizeof(time_diff_t));
	memset(raws, 0, bench->rep_iter * sizeof(time_diff_t));
	if (bench->run_sandboxes) {
		assert(run_transition(sandbox_prefix, bench, results, raws));
		display_transition(sandbox_prefix, bench, results, raws);
		memset(results, 0, bench->rep_iter * sizeof(time_diff_t));
		memset(raws, 0, bench->rep_iter * sizeof(time_diff_t));
	}
	if (bench->run_enclaves) {
		assert(run_transition(enclave_prefix, bench, results, raws));
		display_transition(enclave_prefix, bench, results, raws);
		memset(results, 0, bench->rep_iter * sizeof(time_diff_t));
		memset(raws, 0, bench->rep_iter * sizeof(time_diff_t));
	}
	if (bench->run_carves) {
		assert(run_transition(carve_prefix, bench, results, raws));
		display_transition(carve_prefix, bench, results, raws);
		memset(results, 0, bench->rep_iter * sizeof(time_diff_t));
		memset(raws, 0, bench->rep_iter * sizeof(time_diff_t));
	}
	free(results);
	free(raws);
}

static void proxy_attestation_bench(ubench_config_t *bench) {
	time_diff_t* results = NULL;
	usize *sizes = NULL;
	results = calloc(bench->rep_iter, sizeof(time_diff_t));
	assert(results != NULL);
	sizes = calloc(bench->rep_iter, sizeof(usize));
	assert(results != NULL);
	memset(results, 0, sizeof(time_diff_t)*bench->rep_iter);
	memset(sizes, 0, sizeof(usize)*bench->rep_iter);
	if (bench->run_sandboxes) {
		assert(run_attestation(sandbox_prefix, bench, results, sizes));
		display_attestation(sandbox_prefix, bench, results, sizes);
		memset(results, 0, bench->rep_iter * sizeof(time_diff_t));
		memset(sizes, 0, bench->rep_iter * sizeof(usize));
	}

	if (bench->run_enclaves) {
		assert(run_attestation(enclave_prefix, bench, results, sizes));
		display_attestation(enclave_prefix, bench, results, sizes);
		memset(results, 0, bench->rep_iter * sizeof(time_diff_t));
		memset(sizes, 0, bench->rep_iter * sizeof(usize));
	}

	if (bench->run_carves) {
		assert(run_attestation(carve_prefix, bench, results, sizes));
		display_attestation(carve_prefix, bench, results, sizes);
		memset(results, 0, bench->rep_iter * sizeof(time_diff_t));
		memset(sizes, 0, bench->rep_iter * sizeof(usize));
	}

	free(results);
	free(sizes);
}

// ————————————————————————————— Main function —————————————————————————————— //
int main(void) {
	// Parse the benchmark configuration.
	parse_configuration(&bench);
	// Check that the configuration is correct.
	assert(check_configuration(&bench));
	// Run the selected benchmarks.
	if (bench.run_create_delete) {
		proxy_create_delete_bench(&bench);	
	}
	if (bench.run_transition) {
		proxy_transition_bench(&bench);
	}
	if (bench.run_attestation) {
		proxy_attestation_bench(&bench);
	}
	return 0;
}
