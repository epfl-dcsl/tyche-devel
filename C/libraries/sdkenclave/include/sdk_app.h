#pragma once

#include "enclave_loader.h"

// ————————————— Environment variables to configure the loader —————————————— //

/// Provide a path to the enclave binary or where it should be extracted
/// when it is embedded in the untrusted ELF.
#define ENCL_BIN ("ENCL_BIN")

/// If defined, regardless of the value, the sdk attempts to extract the enclave
/// from the current binary.
#define ENCL_INCL ("ENCL_INCL")

/// If defined, regardless of the value, the binary has already been instrumented.
/// Everything is inside the segments.
#define TYCHOOLS ("TYCHOOLS")

// ——————————————— Helper functions to configure the loading ———————————————— //

int sdk_create_enclave(
    enclave_t* encl,
    char* default_path,
    const char* self,
    char** loaded_enclave,
    usize cores,
    usize traps);
