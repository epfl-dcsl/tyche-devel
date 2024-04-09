#pragma once

#include "common.h"
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

bool run_transition(
		const char* prefix,
		ubench_config_t* bench,
		time_diff_t* results,
		time_diff_t* raws);

void display_transition(
		const char* prefix,
		ubench_config_t* bench,
		time_diff_t* results,
		time_diff_t* raws);

bool run_attestation(
		const char* prefix,
		ubench_config_t* bench,
		time_diff_t* results,
		usize* sizes);

void display_attestation(
		const char* prefix,
		ubench_config_t* bench,
		time_diff_t* results,
		usize* sizes);
