#ifndef __INCLUDE_TYCHE_API_H__
#define __INCLUDE_TYCHE_API_H__

#include "tyche_capabilities_types.h"

/// Copied from the tyche source code
typedef enum tyche_monitor_call_t {
  TYCHE_CREATE_DOMAIN = 1,
  TYCHE_SEAL_DOMAIN = 2,
  TYCHE_SHARE = 3,
  TYCHE_SEND = 4,
  TYCHE_SEGMENT_REGION = 5,
  TYCHE_REVOKE = 6,
  TYCHE_DUPLICATE = 7,
  TYCHE_ENUMERATE = 8,
  TYCHE_SWITCH = 9,
  TYCHE_EXIT = 10,
  TYCHE_CONFIGURE = 12,
  TYCHE_SET_ENTRY_ON_CORE = 13,
} tyche_monitor_call_t;

typedef enum tyche_configurations_t {
  TYCHE_CONFIG_PERMISSIONS = 0,
  TYCHE_CONFIG_TRAPS = 1,
  TYCHE_CONFIG_CORES = 2,
  TYCHE_CONFIG_SWITCH = 3,
} tyche_configurations_t;

#define TYCHE_CAPA_NULL ((capa_index_t)0)

/// Defined in capabilities/src/domain.rs
#define CAPAS_PER_DOMAIN ((capa_index_t)100)

/// A type to pass arguments and receive when calling tyche.
typedef struct vmcall_frame_t {
  // Vmcall id.
  usize vmcall;

  // Arguments.
  usize arg_1;
  usize arg_2;
  usize arg_3;
  usize arg_4;
  usize arg_5;
  usize arg_6;

  // Results.
  usize value_1;
  usize value_2;
  usize value_3;
  usize value_4;
  usize value_5;
  usize value_6;
} vmcall_frame_t;

// —————————————————————————————————— API ——————————————————————————————————— //

int tyche_call(vmcall_frame_t* frame);

int tyche_create_domain(capa_index_t* management);

int tyche_set_cores(capa_index_t management, usize cores);

int tyche_set_traps(capa_index_t management, usize traps);

int tyche_set_perm(capa_index_t management, usize perm);

int tyche_set_switch(capa_index_t management, usize swtype);

int tyche_set_entry(capa_index_t management, usize core, usize cr3, usize rip, usize rsp);

int tyche_seal(capa_index_t* transition, capa_index_t management);

int tyche_segment_region(
    capa_index_t capa,
    capa_index_t* left,
    capa_index_t* right,
    usize a1_1,
    usize a1_2,
    usize a1_3,
    usize a2_1,
    usize a2_2,
    usize a2_3);

int tyche_send(capa_index_t dest, capa_index_t capa);

// TODO: this was removed
int tyche_share(
    capa_index_t* left,
    capa_index_t dest,
    capa_index_t capa,
    usize a1,
    usize a2,
    usize a3);

int tyche_revoke(capa_index_t id);

int tyche_switch(capa_index_t* transition_handle, void* args);

int tyche_duplicate(capa_index_t* new_capa, capa_index_t capa);

#endif
