#pragma once

#include "common.h"

/// Backend-specific implementation of an execution context (vcpu)
struct backend_vcpu_info_t {
  /// Vcpu core id.
  int core_id;

  // Stack pointer.
  usize stack;

  // Program pointer.
  usize rip;

  // Page table root.
  usize cr3;
  /// Allow the vcpus to be in a list.
  dll_elem(struct backend_vcpu_info_t, list);
};

/// Backend-specific info for tyche.
struct backend_info_t {
};
