#ifndef __INCLUDE_ENCLAVE_LOADER_H__
#define __INCLUDE_ENCLAVE_LOADER_H__

#include "elf64.h"
#include "tyche_enclave.h"

/// The representation of an enclave from the user program.
typedef struct {
  /// Enclave driver fd.
  int driver_fd;

  /// Binary ELF fd.
  int elf_fd;

  /// Driver domain handle.
  tyche_encl_handle_t domain_handle;

} enclave_t;

#endif /*__INCLUDE_ENCLAVE_LOADER_H__*/
