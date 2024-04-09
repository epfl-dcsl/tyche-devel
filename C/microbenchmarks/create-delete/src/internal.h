#pragma once

#include "create_delete.h"
#include "measurement.h"
#include <stddef.h>

bool run_internal(
		const char* prefix,
		create_delete_config_t* bench,
		time_diff_t* create_res,
		time_diff_t* delete_res,
		size_t res_size);
