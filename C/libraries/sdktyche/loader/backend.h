#pragma once

/*
 * This is the API for the backends: KVM and the Tyche driver.
 */
#include "sdk_tyche_types.h"

// —————————————————————— Backend specific attributes ——————————————————————— //

#ifdef RUN_WITH_KVM

typedef struct backend_region_t {
  /// The kvm memory region.
  struct kvm_userspace_memory_region kvm_mem;

  /// backend_region_t are stored in a list.
  dll_elem(struct backend_region_t, list);
} backend_region_t;

struct backend_info_t {
  /// File descriptor for memory allocation.
  int memfd;

  /// kvm memory regions.
  dll_list(backend_region_t, kvm_regions);
};

#else
struct backend_info_t {
  // TODO figure out what to do
};
#endif /*RUN_WITH_KVM*/

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
int backend_td_configure(tyche_domain_t* domain);
int backend_td_create_vcpu(tyche_domain_t* domain);
