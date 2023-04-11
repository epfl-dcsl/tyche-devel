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
  memory_access_right_t flags;

  /// Type for the region: {Shared|Confidential}.
  enclave_segment_type_t tpe;

  /// Segments are stored in a double linked list.
  dll_elem(struct enclave_segment_t, list);
} enclave_segment_t;

/// This structure registers segments mapped in the user address space.
typedef struct mmap_segment_t {
  /// The creator's pid.
  pid_t pid;

  /// The virtual start.
  usize virt_start;

  /// The physical start.
  usize phys_start;

  /// The size of the contiguous memory region.
  usize size;

  /// The segments are part of a global list mapped_segments.
  dll_elem(struct mmap_segment_t, list);
} mmap_segment_t;

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

/// Initializes the driver.
void init_enclaves(void);
/// Initializes the capability library.
int init_capabilities(void);
/// Create a new enclave with handle.
int create_enclave(enclave_handle_t handle, usize spawn, usize comm);
/// Handles an mmap call to the driver.
/// This reserves a contiguous region and registers it until an enclave claims it.
int mmap_segment(struct vm_area_struct* vma);
/// Returns the physoffset of the enclave.
/// We expect the handle to be valid, and the virtaddr to exist in segments.
int get_physoffset_enclave(
    enclave_handle_t handle,
    usize virtaddr,
    usize* phys_offset);
/// Sets up access rights and conf|share for the segment.
int mprotect_enclave(
    enclave_handle_t handle,
    usize vstart,
    usize size,
    memory_access_right_t flags,
    enclave_segment_type_t tpe);
/// Commits the enclave. This is where the capability operations are done.
int commit_enclave(enclave_handle_t handle, usize cr3, usize rip, usize rsp);
/// Delete the enclave and revoke the capabilities.
int delete_enclave(enclave_handle_t handle);

#endif /*__SRC_ENCLAVES_H__*/
