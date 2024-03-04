#pragma once

#include "common.h"
#include "common_kvm.h"
#include "dll.h"
#include "tyche_capabilities_types.h"

#include <linux/kvm.h>

// ————————————————————————————————— Types —————————————————————————————————— //
/// Regions for the domain.
typedef struct backend_region_t {
  /// The kvm memory region.
  struct kvm_userspace_memory_region kvm_mem;

  /// Memory protection for the region.
  memory_access_right_t flags;

  /// Whether the region is confidential or not.
  segment_type_t tpe;

  /// backend_region_t are stored in a list.
  dll_elem(struct backend_region_t, list);
} backend_region_t;

/// Backend-specific implementation of an execution context (vcpu)
struct backend_vcpu_info_t {
  /// File descriptor for the vcpu.
  int fd;
  /// Vcpu core id.
  int core_id;
  /// kvm-specific memory mapped structure.
  struct kvm_run* kvm_run;

  /// user registers for the vcpu.
  struct kvm_regs regs;
  /// supervisor registers for the vcpu.
  struct kvm_sregs sregs;
  /// Allow the vcpus to be in a list.
  dll_elem(struct backend_vcpu_info_t, list);
};

/// Backend-specific info for kvm.
struct backend_info_t {
  /// File descriptor for memory allocation.
  int memfd;

  /// Counters for the slot.
  int counter_slots;

  /// size of the structure above.
  int kvm_run_mmap_size;

  /// kvm memory regions.
  dll_list(backend_region_t, kvm_regions);
};
