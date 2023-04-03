#ifndef __INCLUDE_ENCL_LOADER_H__
#define __INCLUDE_ENCL_LOADER_H__

#include "elf64.h"
#include "encl_rt.h"
#include "tyche_enclave.h"

/// Type of entry functions in the enclave.
typedef void (*target_func_t)(void*);

/// The configuration of an enclave library (encl.so).
typedef struct lib_encl_t {
  /// Where the dynload put the library.
  void* plugin;

  /// The size of the gate.
  size_t size;

  /// TODO other gate mechanisms/interfaces provided by encl.so
} lib_encl_t;

// ————————————————————————————— Internal types ————————————————————————————— //

/// encl_create_t holds all the information we need to create an enclave
/// from an mmaped and opened elf binary.
typedef struct load_encl_t {
  /// Enclave driver fd.
  int driver_fd;

  /// Binary ELF fd.
  int elf_fd;

  /// The file that was mmap-ed.
  void* elf_content;

  /// The elf content size.
  size_t elf_size;

  Elf64_Ehdr header;

  /// The ELF sections.
  Elf64_Shdr* sections;

  /// The ELF segments.
  Elf64_Phdr* segments;

  /// The stack segment.
  Elf64_Shdr* stack_section;

  /// The enclave entry point.
  Elf64_Sym* entry_point;

  /// Enclave handle.
  tyche_encl_handle_t handle;

  /// domain handle
  domain_id_t domain_handle;

  /// Where each segment is mapped.
  void** mappings;
  size_t* sizes;
} load_encl_t;

// ——————————————————————————————— Public API ——————————————————————————————— //

/// Initialize the enclave loader with a libencl.
/// The libencl will be mapped by default in all the enclaves.
const lib_encl_t* init_enclave_loader(const char* libencl);

/// Load the enclave defined by the file path, add the extras regions to it,
/// store the resulting enclave definition in the provided enclave pointer.
int load_enclave(const char* file, load_encl_t* enclave,
    struct tyche_encl_add_region_t* extras);

/// Delete an enclave.
/// We reclaim the resources allocated to the enclave and delete the loader and
/// the driver datastructures.
int delete_enclave(load_encl_t* encl);

/// An implementation of the transition that goes through the kernel driver.
/// This allows to disable interrupts before transitioning.
int enclave_driver_transition(domain_id_t handle, void* args);

/// An implementation of the transition directly in use space.
/// We do not disable interrupts before transitioning.
int enclave_user_switch(domain_id_t handle, void* args);
// ————————————————————————————— Debugging API —————————————————————————————— //
void* mmap_file(const char* file, int* fd, size_t* size);
int parse_enclave(load_encl_t* enclave);
int map_enclave(load_encl_t* enclave);
int create_enclave(load_encl_t* enclave, struct tyche_encl_add_region_t* extras);
#endif
