#include "ubench.h"
#include "measurement.h"
#include "common.h"
#include "sdk_tyche.h"
#include "sdk_tyche_rt.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define WIDTH (80)
#define COL_WIDTH (25)

static bool run_create_delete_iterations(
		char* name,
		size_t offset,
		ubench_config_t* bench,
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

bool run_create_delete(
		const char* prefix,
		ubench_config_t* bench,
		time_diff_t* create_res,
		time_diff_t* delete_res,
		size_t res_size) {
	assert(prefix != NULL && bench != NULL && res_size > 0);
	
	for (int i = bench->min; i <= bench->max; i++) {
		char name[100] = {0};
		size_t offset = i - bench->min;
		sprintf(name, "%s/%s", prefix, domain_size_names[i]);
		assert(run_create_delete_iterations(name, offset, bench, create_res, delete_res, res_size));
	}
	return true;
}


static void print_line(const char* col1, const char* col2, const char* col3) {
	int pad = 0;
	assert(col1 != NULL && col2 != NULL && col3 != NULL);
	printf("%s", col1);
	pad = COL_WIDTH - strlen(col1);
	for (int i = 0; i < pad; i++) {
		putchar(' ');
	}
	printf("%s", col2);
	pad = COL_WIDTH - strlen(col2);
	for (int i = 0; i < pad; i++) {
		putchar(' ');
	}
	printf("%s", col3);
	pad = COL_WIDTH - strlen(col3);
	for (int i = 0; i < pad; i++) {
		putchar(' ');
	}
	printf("\n");
}

void display_create_delete(
		const char* prefix, 
		ubench_config_t *bench,
		time_diff_t* create_res,
		time_diff_t* delete_res) {
	assert(prefix != NULL && bench != NULL && create_res != NULL && delete_res != NULL);
	char buf2[COL_WIDTH] = {0};
	char buf3[COL_WIDTH] = {0};
	
	
	// Print the header.
	printf("For %ld iterations\n", bench->nb_iterations);
	sprintf(buf2, "create (%s)", TIME_MEASUREMENT_UNIT);
	sprintf(buf3, "delete (%s)", TIME_MEASUREMENT_UNIT);
	print_line(prefix, buf2, buf3); 	

	// Print the lines
	for (domain_size_t i = bench->min; i <= bench->max; i++) {
		int idx = i - bench->min;
		sprintf(buf2, "%.3f", create_res[idx]);
		sprintf(buf3, "%.3f", delete_res[idx]);
		print_line(domain_size_names[i], buf2, buf3);
	}
	printf("\n");
}
