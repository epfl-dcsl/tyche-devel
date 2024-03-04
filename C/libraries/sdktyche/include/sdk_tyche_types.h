#pragma once

#include "elf64.h"
#include "tyche_capabilities_types.h"
#ifdef RUN_WITH_KVM
#include <linux/kvm.h>
#else
#include "tyche_driver.h"
#endif

#ifdef RUN_WITH_KVM
#include "../loader/backends/back_kvm.h"
#else
#include "../loader/backends/back_tyche.h"
#endif

#include <elf.h>
#include <stdint.h>

// ——————————————————————————————— Constants ———————————————————————————————— //

#define ALL_CORES (~(usize)(0))
#define DEFAULT_CORES ((usize)1)
#define NO_CORES ((usize)(0))
#define ALL_TRAPS (~(usize)(0))
#define NO_TRAPS ((usize)(0))
#define DEFAULT_PERM ((usize)0)

// ————————————————————————————— Tychools Phdrs ————————————————————————————— //
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
// ————————————————————————————————— Types —————————————————————————————————— //

/// Opaque information held by the backend.
typedef struct backend_info_t backend_info_t;

/// Opaque vcpu info held by the backend.
typedef struct backend_vcpu_info_t backend_vcpu_info_t;

/// The fd that represents an domain.
typedef int handle_t;

/// Encapsulates the parser state for a domain.
typedef struct {
  /// The ELF parser.
  elf_parser_t elf;

  /// ELF header.
  Elf64_Ehdr header;

  /// ELF segments, this is an array allocated by elf64.
  Elf64_Phdr* segments;

  /// ELF sections, this is an array allocated by elf64.
  Elf64_Shdr* sections;

  /// ELF strings.
  char* strings;

} parser_t;

/// Describes the memory layout of the domain.
typedef struct {
  /// The virtual offset for the domain.
  usize virtoffset;
  /// The physical offset for the domain.
  usize physoffset;
  /// The overall size of the domain segment.
  usize size;
} domain_map_t;

/// Quick access to shared sections.
typedef struct domain_shared_memory_t {
  Elf64_Phdr* segment;
  /// The address in the untrusted user space.
  usize untrusted_vaddr;
  /// Stored as a list.
  dll_elem(struct domain_shared_memory_t, list);
} domain_shared_memory_t;

/// Configuration for the domain, necessary for proper commit.
typedef struct {
  /// The root page table for the domain.
  usize page_table_root;

  /// The entry point for the domain, parsed from the binary.
  usize entry;

  /// The stack pointer for the domain, parsed from the binary.
  usize stack;

  /// User stack configuration.
  usize user_stack;
} domain_config_t;

/// The representation of a domain.
typedef struct {
  /// Driver domain handle.
  handle_t handle;

  /// Configuration for the commit.
  domain_config_t config;

  /// The parser state for the domain.
  parser_t parser;

  /// The memory layout of the domain.
  domain_map_t map;

  /// The domain's core map.
  usize core_map;

  /// The domain's trap bitmap.
  usize traps;

  /// The domain's permissions.
  usize perms;

  /// List of shared regions.
  dll_list(domain_shared_memory_t, shared_regions);

  /// List of vcpus (contexts) for this domain.
  dll_list(backend_vcpu_info_t, vcpus);

  /// Backend specific fields.
  backend_info_t backend;
} tyche_domain_t;

typedef unsigned long long nonce_t;
