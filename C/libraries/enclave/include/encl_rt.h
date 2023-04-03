#ifndef __INCLUDE_ENCL_RT_H__
#define __INCLUDE_ENCL_RT_H__

#include "tyche_enclave.h"

typedef struct gate_frame_t {
  tyche_encl_handle_t ret;
  void* args;
} gate_frame_t;

typedef struct enclave_entry_t {
  void (*function)(void*);
  void* args;
} enclave_entry_t;

/// This function is called when we first transition into the enclave.
void trusted_entry(capa_index_t ret_handle, void* args);

/// Gate call is used for transitions.
/// It invokes the tyche_encl_handle_t contained in frame.
/// Upon a return to the domain, it updates the ret value as well as the args.
int gate_call(gate_frame_t* frame);
#endif
