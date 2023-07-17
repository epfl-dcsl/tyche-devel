#ifndef __INCLUDE_TYCHE_CAPABILITIES_H__
#define __INCLUDE_TYCHE_CAPABILITIES_H__

#include "ecs.h"
#include "tyche_capabilities_types.h"

// ———————————————————————————————— Globals ————————————————————————————————— //

extern domain_t local_domain;

// —————————————————————————————————— API ——————————————————————————————————— //

/// Initialize the local domain.
/// This function enumerates the regions attributed to this domain and populates
/// the local_domain.
int init(capa_alloc_t allocator, capa_dealloc_t deallocator);

/// Creates a new domain.
/// Sets the result inside the provided id handle.
int create_domain(domain_id_t* id);

/// Seal the domain.
/// This function first creates a channel for the child domain and then seals it.
int seal_domain(domain_id_t id);

/// Duplicate capability.
int segment_region_capa(
    capability_t* capa,
    capability_t** left,
    capability_t** right,
    usize a1_1,
    usize a1_2,
    usize a1_3,
    usize a2_1,
    usize a2_2,
    usize a2_3);

/// Grant a memory region.
/// Finds the correct capability and grants the region to the target domain.
int grant_region(domain_id_t id, paddr_t start, paddr_t end, memory_access_right_t access);

/// Share a memory region.
/// Finds the correct capability and shares the region with the target domain.
int share_region(domain_id_t id, paddr_t start, paddr_t end, memory_access_right_t access);

/// Revoke the memory region.
/// Start and end must match existing bounds on a capability.
int revoke_region(domain_id_t id, paddr_t start, paddr_t end);

/// Switch to the target domain, sets the args in r11.
/// Fails if all transition handles are used.
int switch_domain(domain_id_t id, void* args);

/// Delete a domain.
/// This function goes through all the capabilities in the domain and revokes them.
int revoke_domain(domain_id_t id);

/// Set the core map for a domain.
/// The domain should not be sealed and the map must be a subset of the parent.
int set_domain_cores(domain_id_t id, usize cores);

/// Set the trap bitmap for a domain.
/// The domain should not be sealed and the bitmap must be a subset of the parent.
int set_domain_traps(domain_id_t id, usize traps);

/// Set the permissions for the domain.
/// The domain should not be sealed and the bitmap must be a subset of the parent.
int set_domain_perm(domain_id_t id, usize perm);

/// Set the switch type for the domain.
/// The domain should not be sealed and the value must be defined for the current platform.
int set_domain_switch(domain_id_t id, usize swtype);

/// Set the domain's entry point of the selected core.
int set_domain_entry_on_core(domain_id_t id, usize core, usize cr3, usize rip, usize rsp);

#endif
