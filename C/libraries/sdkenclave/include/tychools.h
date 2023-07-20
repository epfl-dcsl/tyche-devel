#pragma once

// ————————————————————————————————— Types —————————————————————————————————— //

/// OS-specific Phdr (Segments) types.
/// @warn: needs to be synchronized with tychools TychePhdrTypes.
typedef enum {
  /// User stack sandbox (shared) segment.
  USER_STACK_SB = 0x60000001,
  /// User stack confidential segment.
  USER_STACK_CONF = 0x60000002,
  /// User shared segment.
  USER_SHARED = 0x60000003,
  /// User Confidential segment.
  USER_CONFIDENTIAL = 0x60000004,
  /// Page tables sandbox always kernel.
  PAGE_TABLES_SB = 0x60000005,
  /// Page tables sandbox always kernel.
  PAGE_TABLES_CONF = 0x60000006,
  /// Kernel stack sandbox segment.
  KERNEL_STACK_SB = 0x60000007,
  /// Kernel stack segment.
  KERNEL_STACK_CONF = 0x60000008,
  /// Kernel shared segment.
  KERNEL_SHARED = 0x60000009,
  /// Kernel Confidential segment.
  KERNEL_CONFIDENTIAL = 0x6000000a,
} tyche_phdr_t;

// ———————————————————————————— Helper functions ———————————————————————————— //

/// Determines whether a segment type is confidential.
int is_confidential(tyche_phdr_t tpe);

/// Determines whether a segment type is loadable.
int is_loadable(tyche_phdr_t tpe);
