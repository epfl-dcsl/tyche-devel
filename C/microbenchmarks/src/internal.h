#pragma once

#include "measurement.h"
#include "ubench.h"
#include <stddef.h>

bool run_create_delete(
		const char* prefix,
		ubench_config_t* bench,
		time_diff_t* create_res,
		time_diff_t* delete_res,
		size_t res_size);

void display_create_delete(
		const char* prefix,
		ubench_config_t* bench,
		time_diff_t* create_res,
		time_diff_t* delete_res);
