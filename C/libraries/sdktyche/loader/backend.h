#pragma once

/*
 * This is the API for the backends: KVM and the Tyche driver.
 */
#include "sdk_tyche_types.h"

// —————————————————————— Backend specific attributes ——————————————————————— //

typedef struct backend_info_t backend_info_t;

// —————————————————————————————————— API ——————————————————————————————————— //

/// Create the domain with the backend.
int backend_td_create(tyche_domain_t* domain);
/// Allocate memory for the domain.
int backend_td_alloc_mem(tyche_domain_t* domain);
/// Register a region for the domain.
int backend_td_register_region(
    tyche_domain_t* domain,
    usize vstart,
    usize size,
    memory_access_right_t flags,
    segment_type_t tpe);
int backend_td_commit(tyche_domain_t* domain);
int backend_td_delete(tyche_domain_t* domain);
int backend_td_config(tyche_domain_t* domain, usize config, usize value);
int backend_td_create_vcpu(tyche_domain_t* domain, usize core_idx);
int backend_td_init_vcpu(tyche_domain_t* domain, usize core_idx);
// int backend_td_config_vcpu(tyche_domain_t* domain, usize field, usize value);
int backend_td_vcpu_run(tyche_domain_t* domain, usize core);
