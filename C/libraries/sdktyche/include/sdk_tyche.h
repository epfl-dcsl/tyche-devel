#pragma once

#include "sdk_tyche_types.h"
#include "tyche_capabilities_types.h"

// ————————————— Environment variables to configure the loader —————————————— //

/// Provide a path where a binary should be extracted
#define DUMP_BIN ("DUMP_BIN")

// ——————————————————————————————— Constants ———————————————————————————————— //

#define MAX_CORES (32)
#define MAX_SLOT_SIZE (0x400000)
// ————————————————————————————— SDK Tyche API —————————————————————————————— //
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
int sdk_call_domain(tyche_domain_t* domain);

/// Transitions into the domain on a specific core.
/// @warning: fails when called from a different core.
int sdk_call_domain_on_core(tyche_domain_t* domain, usize core);

/// Delete the domain.
int sdk_delete_domain(tyche_domain_t* domain);

// ——————————————————— Helper functions for applications ———————————————————— //

/// Returns the number of cores on the machine.
int sdk_get_core_count(void);

/// Returns the mask to run on all available cores.
usize sdk_all_cores_mask(void);

/// Sets the affinity of the thread so the current core.
/// exits the program on failure.
/// Returns the bitmap with a single core enabled.
usize sdk_pin_to_current_core(void);
