#ifndef __INCLUDE_TYCHE_CAPABILITIES_TYPES_H__
#define __INCLUDE_TYCHE_CAPABILITIES_TYPES_H__

#ifndef NULL
#define NULL ((void*)0)
#endif

#include "common.h"
#include "dll.h"

typedef unsigned long long usize;

#define ALL_CORES_MAP (~((usize)0))
#define NO_CPU_SWITCH (~((usize)0))
/// Internal definition of our types so we can move to 32 bits.
typedef long long unsigned int paddr_t;

/// Internal definition of domain id.
typedef unsigned long long domain_id_t;

/// Internal definition of index.
typedef unsigned long long capa_index_t;

/// Type of a capability
typedef enum capa_type_t {
  Region = 0,
  Management = 1,
  Channel = 2,
  Switch = 3,
} capa_type_t;

/// Status of a domain capability.
typedef enum domain_status_t {
  None = 0,
  Unsealed = 1,
  Sealed = 2,
} domain_status_t;

/// Define what should be private to a domain.
typedef enum switch_save_t {
  /// Reference the same vcpu.
  SharedVCPU = 1,
  /// New VCPU, copy state.
  CopyVCPU = 2,
  /// New VCPU, raw (for VMs).
  FreshVCPU = 3,
} switch_save_t;

/// Region Access Rights
typedef enum memory_access_right_t {
  MEM_ACTIVE = 1 << 0,
  MEM_CONFIDENTIAL = 1 << 1,
  MEM_READ = 1 << 2,
  MEM_WRITE = 1 << 3,
  MEM_EXEC = 1 << 4,
  MEM_SUPER = 1 << 5,
} memory_access_right_t;

/// Access right information for a region capability.
typedef struct capa_region_t {
  paddr_t start;
  paddr_t end;
  memory_access_right_t flags;
} capa_region_t;

/// Information about a domain management capability.
typedef struct capa_management_t {
  domain_status_t status;
  capa_index_t id;
} capa_management_t;

typedef struct capa_channel_t {
  //TODO what id is this?
  capa_index_t id;
} capa_channel_t;

typedef struct capa_switch_t {
  //TODO what id is this?
  capa_index_t id;
  // TODO: add reference about the domain?
} capa_switch_t;

/// A capability can be any of these three types.
typedef union capa_descriptor_t {
  capa_region_t region;
  capa_management_t management;
  capa_channel_t channel;
  capa_switch_t transition;
} capa_descriptor_t;

/// Capability that confers access to a memory region.
typedef struct capability_t {
  // General capability information.
  capa_index_t local_id;
  capa_type_t capa_type;
  capa_descriptor_t info;

  // Tree structure.
  // TODO: do we still need this?
  struct capability_t* parent;
  struct capability_t* left;
  struct capability_t* right;

  // This structure can be put in a double-linked list
  dll_elem(struct capability_t, list);
} capability_t;

typedef void* (*capa_alloc_t)(unsigned long size);
typedef void (*capa_dealloc_t)(void* ptr);
typedef void (*capa_dbg_print_t)(const char* msg);

/// Represents the current domain's metadata.
typedef struct domain_t {
  // Allocate ids from this counter for children domains.
  domain_id_t id_counter;
  domain_id_t id;

  // The allocator to use whenever we need a new structure.
  capa_alloc_t alloc;
  capa_dealloc_t dealloc;
  capa_dbg_print_t print;

  // All the children for this domain.
  dll_list(struct child_domain_t, children);

  // The list of used capabilities for this domain.
  dll_list(struct capability_t, capabilities);
} domain_t;

typedef enum transition_lock_t {
  TRANSITION_UNLOCKED = 0,
  TRANSITION_LOCKED = 1,
} transition_lock_t;

/// Wrapper around transition handles.
/// This allows to add a lock.
typedef struct transition_t {
  transition_lock_t lock;
  capability_t* transition;
  dll_elem(struct transition_t, list);
} transition_t;

/// Represents a child domain.
/// We keep track of:
/// 1) The main communication channel.
/// 2) The revocation handle to kill the domain.
/// 3) All the resources we passed to the domain.
typedef struct child_domain_t {
  // The domain's local id.
  domain_id_t id;

  // Handle to the domain
  capability_t* management;

  // All the revocations for resources passed to the domain.
  dll_list(struct capability_t, revocations);

  // All the transition handles to this domain.
  dll_list(struct transition_t, transitions);

  // This structure can be put in a double-linked list.
  dll_elem(struct child_domain_t, list);
} child_domain_t;

#endif
