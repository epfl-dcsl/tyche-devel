#pragma once

/// Backend-specific implementation of an execution context (vcpu)
struct backend_vcpu_info_t {
  /// Vcpu core id.
  int vcpu_core_id;

  /// TODO figure out what to put there.

  /// Allow the vcpus to be in a list.
  dll_elem(struct backend_vcpu_info_t, list);
};

/// Backend-specific info for tyche.
struct backend_info_t {
};
