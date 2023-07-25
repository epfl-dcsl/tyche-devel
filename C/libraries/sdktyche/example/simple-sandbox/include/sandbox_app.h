#pragma once

#define SHARED_BUFFER (0x300000)

/// Configuration for the enclave.
/// This allows to select which example to run via shared memory.
typedef struct {
  /// arguments for this application.
  void* args;
} config_t;

/// WRITE_RO argument.
typedef struct {
  char buffer[30];
} write_ro_t;
