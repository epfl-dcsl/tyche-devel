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
int create_domain(domain_id_t* id, usize spawn, usize comm);

/// Seal the domain.
/// This function first creates a channel for the child domain and then seals it.
int seal_domain(
    domain_id_t id,
    usize core_map,
    usize cr3,
    usize rip,
    usize rsp);

/// Duplicate capability.
int duplicate_capa(
    capability_t** left,
    capability_t** right,
    capability_t* capa,
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

#endif
