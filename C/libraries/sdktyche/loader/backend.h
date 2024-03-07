#pragma once

/*
 * This is the API for the backends: KVM and the Tyche driver.
 */
#include "sdk_tyche_types.h"

// —————————————————————— Backend specific attributes ——————————————————————— //

typedef struct backend_info_t backend_info_t;

// ————————————————————————————— Default values ————————————————————————————— //

// Bitmap of selected extensions.
// PSE: 4
// PAE: 5
// MCE: 6
// PGE: 7
// OSFXSR: 9
// OSXMMEXCPT: 10
// UMIP: 11
// FSGSBASE: 16
// OSXSAVE: 18
// SMEP: 20
#define DEFAULT_CR4 ((1U << 4) | (1U << 5) | (1U << 6) | (1U << 7) | (1U << 9) | (1U << 10) | (1U << 11) | (1U << 16) | (1U << 18) | (1U << 20))

// VMXE: 13
#define DEFAULT_CR4_EXTRAS ((1 << 13))

#define DEFAULT_CR0 (0x80050033)

#define DEFAULT_EFER (0xd01)

#define DEFAULT_RFLAGS_INTERRUPTS_OFF (0x092)

#define DEFAULT_RFLAGS_INTERRUPTS_ON (0x286)
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
