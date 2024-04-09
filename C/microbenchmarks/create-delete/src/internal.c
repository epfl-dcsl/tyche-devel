#include "create_delete.h"
#include "measurement.h"
#include "common.h"
#include "sdk_tyche.h"
#include "sdk_tyche_rt.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>


static bool run_iterations(
		char* name,
		size_t offset,
		create_delete_config_t* bench,
		time_diff_t* create_res,
		time_diff_t* delete_res,
		size_t res_size) {
	assert(name != NULL && bench != NULL);
	time_measurement_t start;
	time_measurement_t end;

	tyche_domain_t* domains = calloc(bench->nb_iterations, sizeof(tyche_domain_t));
	assert(domains != NULL);

	assert(take_time(&start));
	for (int i = 0; i < bench->nb_iterations; i++) {
		assert(sdk_create_domain(&domains[i], name, 1, NO_TRAPS, DEFAULT_PERM) == SUCCESS);
	}
	assert(take_time(&end));
	assert(create_res != NULL);
	create_res[offset] = compute_elapsed(&start, &end);

	// Delete
	assert(take_time(&start));
	for (int i = 0; i < bench->nb_iterations; i++) {
		assert(sdk_delete_domain(&domains[i]) == SUCCESS);
	}
	assert(take_time(&end));
	delete_res[offset] = compute_elapsed(&start, &end);
	return true;
}


bool run_internal(
		const char* prefix,
		create_delete_config_t* bench,
		time_diff_t* create_res,
		time_diff_t* delete_res,
		size_t res_size) {
	assert(prefix != NULL && bench != NULL && res_size > 0);
	
	for (int i = bench->min; i <= bench->max; i++) {
		char name[100] = {0};
		size_t offset = i - bench->min;
		sprintf(name, "%s/%s", prefix, domain_size_names[i]);
		assert(run_iterations(name, offset, bench, create_res, delete_res, res_size));
	}
	return true;
}
