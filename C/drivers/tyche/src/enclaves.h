#ifndef __SRC_ENCLAVES_H__
#define __SRC_ENCLAVES_H__

#include <linux/mm_types.h>

#include "dll.h"
#include "tyche_capabilities_types.h"
#define _IN_MODULE
#include "tyche_enclave.h"
#undef _IN_MODULE

// ————————————————————————————————— Types —————————————————————————————————— //

#define UNINIT_USIZE (~((usize)0))
#define UNINIT_DOM_ID (~((domain_id_t)0))

/// Describes an enclave's memory segment in user process address space.
typedef struct enclave_segment_t {
  /// Start of the virtual memory segment.
  usize vstart;

  /// Size of the memory segment.
  usize size;

  /// Protection flags.
  usize flags;

  /// Type for the region: {Shared|Confidential}.
  enclave_segment_type_t tpe;

  /// Segments are stored in a double linked list.
  dll_elem(struct enclave_segment_t, list);
} enclave_segment_t;

/// Describes an enclave.
typedef struct enclave_t {
  /// The creator task's pid.
  pid_t pid;

  /// The enclave's handle within the driver.
  enclave_handle_t handle;

  /// The enclave's domain id.
  domain_id_t domain_id;

  /// The start of the enclave's physical contiguous memory region.
  usize phys_start;

  /// The start of the enclave's virtual memory region in the untrusted process.
  usize virt_start;

  /// The size of the enclave's contiguous memory region.
  usize size;

  /// The segments for the enclave.
  dll_list(enclave_segment_t, segments);

  /// Domains are stored in a global list by the driver.
  dll_elem(struct enclave_t, list);
} enclave_t;

// ——————————————————————————————— Functions ———————————————————————————————— //

void init_enclaves(void);
int init_capabilities(void);
int mmap_enclave(enclave_handle_t handle, struct vm_area_struct* vma);
int get_physoffset_enclave(enclave_handle_t handle, usize* phys_offset);
int mprotect_enclave(
    enclave_handle_t handle,
    usize vstart,
    usize size,
    usize flags,
    enclave_segment_type_t tpe);
int commit_enclave(enclave_handle_t handle, usize cr3, usize rip, usize rsp);

#endif /*__SRC_ENCLAVES_H__*/
