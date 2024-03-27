#ifndef __INCLUDE_ENCLAVE_APP_H__
#define __INCLUDE_ENCLAVE_APP_H__

/// Configuration for the enclave.
/// This allows to select which example to run via shared memory.
typedef struct {
	/// arguments for this application.
	void* args;
} config_t;

#endif
