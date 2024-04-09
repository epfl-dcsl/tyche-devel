#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "create_delete.h"
#include "common.h"


// ————————————————————————————— Useful defines ————————————————————————————— //

#define DECLARE_PARSER(name, tpe, fn_raw)\
	static void parse_##name##_f(create_delete_config_t* bench, char* value) {\
		tpe result; \
		if (bench == NULL || value == NULL) {\
			return;\
		}\
		if (fn_raw(value, &result) == SUCCESS) {\
			bench->name = result;\
		}\
	}

// —————————————————————————————— Local Types ——————————————————————————————— //

/// Type for functions that process the environment variables.
typedef void (*env_parser_fn)(create_delete_config_t*, char*);


// ———————————————————————————— Global Constants ———————————————————————————— //
const char* env_variables[NB_ENV_VARS] = {
	RUN_ENCLAVES,
	RUN_SANDBOXES,
	RUN_MIN,
	RUN_MAX,
	RUN_NB_ITER,
};

// ———————————————————————————— Static Functions ———————————————————————————— //

/// Parse a bool from a string.
static int parse_bool(char* value, bool* result) {
	if (value == NULL || result == NULL) {
		goto failure;
	}
	if (strcmp(value, "true") == 0 ||
			strcmp(value, "True") == 0 ||
			strcmp(value, "TRUE") == 0 ||
			strcmp(value, "1") == 0) {
		*result = true;
		return SUCCESS;
	}
	if (strcmp(value, "false") == 0 ||
			strcmp(value, "False") == 0 ||
			strcmp(value, "FALSE") == 0 ||
			strcmp(value, "0") == 0) {
		*result = false;
		return SUCCESS;
	}
failure:
	return FAILURE;
}

/// Parse a domain size from a string.
static int parse_size(char* value, domain_size_t* size) {
	if (value == NULL || size == NULL) {
		goto failure;
	}
	for (int i = S_8k; i <= S_10M; i++) {
		if (strcmp(domain_size_names[i], value) == 0) {
			*size = i;
			return SUCCESS;
		}
	}
failure:
	return FAILURE;
}

static int parse_size_t(char* value, size_t* size) {
	unsigned long v = 0;
	char *endptr = NULL;
	if (value == NULL || size == NULL) {
		goto failure;
	}
	v = strtoul(value, &endptr, 10);
	if (errno != 0 || (v == ULONG_MAX)) {
		goto failure;
	}
	*size = v;
	return SUCCESS;
failure:
	return FAILURE;
}

/// Boolean parsers.
DECLARE_PARSER(run_sandboxes, bool, parse_bool);
DECLARE_PARSER(run_enclaves, bool, parse_bool);
// Domain size parsers.
DECLARE_PARSER(min, domain_size_t, parse_size);
DECLARE_PARSER(max, domain_size_t, parse_size);
/// Parser for size_t.
DECLARE_PARSER(nb_iterations, size_t, parse_size_t);

// ————————————————————————————— API functions —————————————————————————————— //

/// The array of parsers.
env_parser_fn parsers[NB_ENV_VARS] = {
	parse_run_sandboxes_f,
	parse_run_enclaves_f,
	parse_min_f,
	parse_max_f,
	parse_nb_iterations_f,
};

/// Parses the configuration from evironment variables.
void parse_configuration(create_delete_config_t* bench) {
	for (int i = 0; i < NB_ENV_VARS; i++) {
		char* value = getenv(env_variables[i]);
		if (value != NULL) {
			continue;
		}
		parsers[i](bench, value);
	}
}
