#pragma once

#include "ubench.h"

// ———————————————————————————————— Globals ————————————————————————————————— //

/// The list of environment variables names.
extern const char* env_variables[NB_ENV_VARS];

// ————————————————————————————— API functions —————————————————————————————— //

/// Parses environment variables and updates the bench configuration accordingly.
void parse_configuration(ubench_config_t* bench);
