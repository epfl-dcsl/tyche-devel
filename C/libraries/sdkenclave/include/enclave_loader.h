#ifndef __INCLUDE_ENCLAVE_LOADER_H__
#define __INCLUDE_ENCLAVE_LOADER_H__

#include "elf64.h"
#include "pts_api.h"
#include "tyche_enclave.h"

#include <elf.h>
#include <stdint.h>

// ——————————————————————————————— Constants ———————————————————————————————— //

#define PAGE_SIZE ((uint64_t)(0x1000))
#define ENTRIES_PER_PAGE (512)

#define ALL_CORES (~(usize)(0))
#define NO_CORES ((usize)(0))
#define ALL_TRAPS (~(usize)(0))
#define NO_TRAPS ((usize)(0))

#define ENCLAVE_DRIVER ("/dev/tyche")
#define SHARED_PREFIX (".tyche_shared")

// ————————————————————————————————— Types —————————————————————————————————— //

/// The fd that represents an enclave.
typedef int handle_t;

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
} enclave_map_t;

/// Describes the type of shared memory: segment or section.
typedef enum {
  TYCHE_SHARED_SECTION = 0,
  TYCHE_SHARED_SEGMENT = 1,
} shared_memory_t;

/// Quick access to shared sections.
typedef struct enclave_shared_memory_t {
  shared_memory_t tpe;
  /// Reference to the shared segment or section.
  union {
    Elf64_Shdr* section;
    Elf64_Phdr* segment;
  } shared;
  /// The address in the untrusted user space.
  usize untrusted_vaddr;
  /// Stored as a list.
  dll_elem(struct enclave_shared_memory_t, list);
} enclave_shared_memory_t;

/// In the first case, we use the bump allocator and generate page tables.
/// In the second case, pages are already instrumented.
typedef enum {
  LEGACY_LOADER = 0,
  TYCHOOL_LOADER = 1,
} tyche_config_t;

/// Configuration for the enclave, necessary for proper commit.
typedef struct {
  /// Determine the loader type.
  tyche_config_t loader_type;

  /// The root page table for the enclave.
  usize cr3;

  /// The entry point for the enclave, parsed from the binary.
  usize entry;

  /// The stack pointer for the enclave, parsed from the binary.
  usize stack;

  /// User stack configuration.
  usize user_stack;

  /// List of shared sections.
  dll_list(enclave_shared_memory_t, shared_sections);

} enclave_config_t;

/// The representation of an enclave from the user program.
typedef struct {
  /// Driver domain handle.
  handle_t handle;

  /// Configuration for the commit.
  enclave_config_t config;

  /// The parser state for the enclave.
  parser_t parser;

  /// The memory layout of the enclave.
  enclave_map_t map;

  /// The enclave's core map.
  usize core_map;

  /// The enclave's trap bitmap.
  usize traps;
} enclave_t;

// —————————————————————————————————— API ——————————————————————————————————— //

/// Look for the enclave binary inside the current program's binary.
/// If found, it extracts it and writes in into the dest file.
int extract_enclave(const char* self, const char* dest);

/// Combines parse and load enclave into one call.
/// Specifies default values for the traps and cores.
int init_enclave(enclave_t* enclave, const char* file);

/// Similar init_enclave but allows to specify cores and traps.
int init_enclave_with_cores_traps(
    enclave_t* enclave,
    const char* file,
    usize cores,
    usize traps);

/// Parse the ELF and compute the page tables (still need to be patched).
int parse_enclave(enclave_t* enclave, const char* file);

/// Loads the enclave, needs to be parsed first.
int load_enclave(enclave_t* enclave);

/// Transitions into the enclave.
int call_enclave(enclave_t* enclave, void* args);

/// Delete the enclave.
int delete_enclave(enclave_t* enclave);

/// Translate ELF flags into tyche memory access rights.
memory_access_right_t translate_flags_to_tyche(Elf64_Word flags);

// ———————————————————————— Tychools compatible API ————————————————————————— //

/// Calls both parse and load enclave pointed by the file.
int tychools_init_enclave_with_cores_traps(
    enclave_t* enclave,
    const char* file,
    usize cores,
    usize traps);

/// Parses an ELF binary created by tychools.
/// All the segments for the enclave should have OS-specific types.
/// The page tables must be present, as well as the stacks and shared regions.
int tychools_parse_enclave(enclave_t* enclave, const char* file);

/// Loads an enclave created with tychools.
/// It patches the page tables that should be located inside one of the segments.
int tychools_load_enclave(enclave_t* enclave);

#endif /*__INCLUDE_ENCLAVE_LOADER_H__*/
