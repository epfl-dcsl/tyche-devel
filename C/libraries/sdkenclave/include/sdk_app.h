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

/// Creates an enclave by parsing environment variables.
/// It checks whether the binary is included (ENCL_INCL=X), if it is already
/// instrumented (TYCHOOLS=X), and if so, extracts it into ENCL_BIN.
/// Otherwise, it uses the default_path for the enclave.
/// The loaded_enclave, if not NULL, is set to the enclave file selected after
/// parsing the environment variables.
int sdk_create_enclave(
    enclave_t* encl,
    char* default_path,
    const char* self,
    char** loaded_enclave,
    usize cores,
    usize traps);
