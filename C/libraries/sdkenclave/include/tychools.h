#pragma once

// ————————————————————————————————— Types —————————————————————————————————— //

/// OS-specific Phdr (Segments) types.
/// @warn: needs to be synchronized with tychools TychePhdrTypes.
typedef enum {
  /// User stack segment.
  USER_STACK = 0x60000001,
  /// User shared segment.
  USER_SHARED = 0x60000002,
  /// User Confidential segment.
  USER_CONFIDENTIAL = 0x60000003,
  /// Page tables are always kernel.
  PAGE_TABLES = 0x60000004,
  /// Kernel stack segment.
  KERNEL_STACK = 0x60000005,
  /// Kernel shared segment.
  KERNEL_SHARED = 0x60000006,
  /// Kernel Confidential segment.
  KERNEL_CONFIDENTIAL = 0x60000007,
} tyche_phdr_t;

// ———————————————————————————— Helper functions ———————————————————————————— //

/// Determines whether a segment type is confidential.
int is_confidential(tyche_phdr_t tpe);

/// Determines whether a segment type is loadable.
int is_loadable(tyche_phdr_t tpe);
