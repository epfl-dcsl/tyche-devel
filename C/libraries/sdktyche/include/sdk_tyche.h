#pragma once

#include "sdk_tyche_types.h"
#include "tyche_capabilities_types.h"

// ————————————— Environment variables to configure the loader —————————————— //

/// Provide a path where a binary should be extracted
#define DUMP_BIN ("DUMP_BIN")

// ——————————————————————————————— Constants ———————————————————————————————— //

#define MAX_CORES (32)

// ——————————————— Helper functions to configure the loading ———————————————— //

/// Creates a domain by parsing the current program and extracting the nested
/// binary. It then instantiates the domain's binary.
/// If the DUMP_BIN environment variable is set, the loaded binary is dumped
/// in the file specified by DUMP_BIN.
int sdk_create_domain(
    tyche_domain_t* encl,
    const char* self,
    usize cores,
    usize traps,
    usize perms);

/// Transitions into the domain.
int sdk_call_domain(tyche_domain_t* domain, usize core);

/// Delete the domain.
int sdk_delete_domain(tyche_domain_t* domain);
