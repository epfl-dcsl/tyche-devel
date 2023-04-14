#ifndef __INCLUDE_ENCLAVE_LOADER_H__
#define __INCLUDE_ENCLAVE_LOADER_H__

#include "elf64.h"
#include "pts_api.h"
#include "tyche_enclave.h"

#include <stdint.h>

// ——————————————————————————————— Constants ———————————————————————————————— //

#define PAGE_SIZE ((uint64_t)(0x1000))
#define ENTRIES_PER_PAGE (512)

// ————————————————————————————————— Types —————————————————————————————————— //

typedef struct __attribute__((__packed__)) __attribute__((aligned(4096))) {
  uint64_t data[ENTRIES_PER_PAGE];
} page_t;

/// The page tables rely on a bump allocator.
/// The allocator itself is just a large region that we mmap.
/// The layout in physical memory is expected to be as follows:
/// |--------- segment 1 ---------]
/// |--------- segment 2 ---------]
///            .........
/// |---------  pages[0] ---------] <- phys_offset
/// |---------  pages[1] ---------]
///            .........
typedef struct {
  /// Index of the next free page.
  int idx;

  /// Buffer of pages;
  page_t* pages;

  /// Physical memory offset for the allocator.
  uint64_t phys_offset;

} page_tables_t;

/// Extra information we carry in the mapper.
typedef struct {
  /// A reference to the bump allocator.
  page_tables_t* bump;
  /// Intermediary flags used when mapping pages.
  uint64_t intermed_flags;
  /// Segment we are mapping.
  Elf64_Phdr* segment;
  /// Segment offset in memory.
  uint64_t segment_offset;
} info_t;

addr_t align_up(addr_t addr);

/// Encapsulates the parser state for an enclave.
typedef struct {
  /// The file descriptor for the ELF.
  int fd;

  /// ELF header.
  Elf64_Ehdr header;

  /// ELF segments, this is an array allocated by elf64.
  Elf64_Phdr* segments;

  /// ELF sections, this is an array allocated by elf64.
  Elf64_Shdr* sections;

  /// ELF strings.
  char* strings;

  /// Bump allocator for the page tables.
  page_tables_t bump;

} parser_t;

/// Describes the memory layout of the enclave.
typedef struct {
  /// The virtual offset for the enclave.
  usize virtoffset;
  /// The physical offset for the enclave.
  usize physoffset;
  /// The overall size of the enclave segment.
  usize size;
  /// Entry point.
  usize vaddr_entry;
  /// Stack.
  usize vaddr_stack;
  /// Page table address.
  usize paddr_page_tables;
} enclave_map_t;

/// Quick access to shared sections.
typedef struct enclave_shared_section_t {
  /// Reference to the section.
  Elf64_Shdr* section;
  /// The address in the untrusted user space.
  usize untrusted_vaddr;
  /// Stored as a list.
  dll_elem(struct enclave_shared_section_t, list);
} enclave_shared_section_t;

/// Configuration for the enclave, necessary for proper commit.
typedef struct {
  /// The root page table for the enclave.
  usize cr3;

  /// The entry point for the enclave, parsed from the binary.
  usize entry;

  /// The stack pointer for the enclave, parsed from the binary.
  usize stack;

  /// List of shared sections.
  dll_list(enclave_shared_section_t, shared_sections);

} enclave_config_t;

/// The representation of an enclave from the user program.
typedef struct {
  /// Enclave driver fd.
  int driver_fd;

  /// Driver domain handle.
  enclave_handle_t handle;

  /// Configuration for the commit.
  enclave_config_t config;

  /// The parser state for the enclave.
  parser_t parser;

  /// The memory layout of the enclave.
  enclave_map_t map;
} enclave_t;

// —————————————————————————————————— API ——————————————————————————————————— //

/// Combines parse and load enclave into one call.
int init_enclave(enclave_t* enclave, const char* file);

/// Parse the ELF and compute the page tables (still need to be patched).
int parse_enclave(enclave_t* enclave, const char* file);

/// Loads the enclave, needs to be parsed first.
int load_enclave(enclave_t* enclave);

/// Transitions into the enclave.
int call_enclave(enclave_t* enclave, void* args);

/// Delete the enclave.
int delete_enclave(enclave_t* enclave);

#endif /*__INCLUDE_ENCLAVE_LOADER_H__*/
