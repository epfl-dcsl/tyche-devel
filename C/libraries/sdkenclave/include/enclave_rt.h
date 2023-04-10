#ifndef __INCLUDE_ENCLAVE_RT_H__
#define __INCLUDE_ENCLAVE_RT_H__

#include "tyche_capabilities_types.h"
// ——————————————————————————————— Constants ———————————————————————————————— //

#define DEFAULT_SHARED_BUFFER_SIZE 0x1000
#define DEFAULT_STACK_SIZE 0x6000

// ————————————————————————————————— Types —————————————————————————————————— //

/// Represents a call frame for the enclave.
typedef struct {
  /// Return handle for this frame.
  capa_index_t ret_handle;

  /// Arguments carrying whatever we need.
  void* args;
} frame_t;

// —————————————————————————————————— API ——————————————————————————————————— //
int gate_call(frame_t* frame);
void trusted_main(capa_index_t ret_handle, void* args);
#endif
