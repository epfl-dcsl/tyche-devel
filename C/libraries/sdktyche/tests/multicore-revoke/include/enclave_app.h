#ifndef __INCLUDE_ENCLAVE_APP_H__
#define __INCLUDE_ENCLAVE_APP_H__

/// Configuration for the enclave.
/// This allows to select which example to run via shared memory.

#define MAGIC_VALUE (0x6789)

typedef struct {
  int flag;
} config_t;

#endif
