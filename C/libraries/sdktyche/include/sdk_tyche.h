#pragma once

#include "sdk_tyche_types.h"

// ————————————— Environment variables to configure the loader —————————————— //

/// Provide a path where a binary should be extracted
#define DUMP_BIN ("DUMP_BIN")

// ——————————————— Helper functions to configure the loading ———————————————— //

/// Creates a domain by parsing the current program and extracting the nested
/// binary. It then instantiates the domain's binary.
/// If the DUMP_BIN environment variable is set, the loaded binary is dumped
/// in the file specified by DUMP_BIN.
int sdk_create_domain(
    tyche_domain_t* encl,
    const char* self,
    usize cores,
    usize traps);

/// Transitions into the domain.
int sdk_call_domain(tyche_domain_t* domain, void* args);

/// Delete the domain.
int sdk_delete_domain(tyche_domain_t* domain);
