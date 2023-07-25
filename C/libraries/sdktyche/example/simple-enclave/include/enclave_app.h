#ifndef __INCLUDE_ENCLAVE_APP_H__
#define __INCLUDE_ENCLAVE_APP_H__

/// Configuration for the enclave.
/// This allows to select which example to run via shared memory.
typedef struct {
  /// arguments for this application.
  void* args;
} config_t;

/// Hello world argument.
typedef struct {
  char reply[30];
} hello_world_t;

#endif
