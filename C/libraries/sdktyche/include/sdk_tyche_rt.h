#pragma once

#include "tyche_capabilities_types.h"

// ——————————————————————————————— Constants ———————————————————————————————— //

#define STACK_OFFSET_TOP ((usize)4)

// ————————————————————————————————— Types —————————————————————————————————— //

/// Represents a call frame for the domain.
typedef struct {
  /// Return handle for this frame.
  capa_index_t ret_handle;

  /// Arguments carrying whatever we need.
  void* args;
} frame_t;

// —————————————————————————————————— API ——————————————————————————————————— //
int gate_call(frame_t* frame);
void trusted_main(capa_index_t ret_handle, void* args);
void* get_default_shared_buffer();
