#pragma once

#include "common.h"
#include "measurement.h"
#include "ubench.h"
#include <stddef.h>

typedef void (*bench_f)(char*, ubench_config_t*);

void run_creation(char* prefix, ubench_config_t* bench);

void run_transition(char* prefix, ubench_config_t* bench);

void run_attestation(char* prefix, ubench_config_t* bench);

void run_hwcomm(char* prefix, ubench_config_t* bench);
