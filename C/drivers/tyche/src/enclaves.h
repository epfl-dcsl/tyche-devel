#ifndef __SRC_ENCLAVES_H__
#define __SRC_ENCLAVES_H__

#include <linux/fs.h>
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

/// An entry point on a core for the enclave.
typedef struct enclave_entry_t {
  usize cr3;
  usize rip;
  usize rsp;
} enclave_entry_t;

/// All entry points for the enclave.
typedef struct enclave_entries_t {
  /// One entry per core, total number of entries.
  size_t size;
  /// The entries dynamically allocated.
  enclave_entry_t* entries;
} enclave_entries_t;

/// Describes an enclave.
typedef struct enclave_t {
  /// The creator task's pid.
  pid_t pid;

  /// The enclave's handle within the driver.
  struct file* handle;
  //enclave_handle_t handle;

  /// The enclave's domain id.
  domain_id_t domain_id;

  /// The start of the enclave's physical contiguous memory region.
  usize phys_start;

  /// The start of the enclave's virtual memory region in the untrusted process.
  usize virt_start;

  /// The size of the enclave's contiguous memory region.
  usize size;

  /// The enclave's traps.
  usize traps;

  /// The enclave's core map.
  usize cores;

  /// The enclave's permission.
  usize perm;

  /// The enclave's switch value.
  usize switch_type;

  /// The enclave's entry points per core.
  enclave_entries_t entries;

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
int create_enclave(enclave_handle_t handle);
/// Handles an mmap call to the driver.
/// This reserves a contiguous region and registers it until an enclave claims it.
int mmap_segment(enclave_handle_t enclave, struct vm_area_struct* vma);
/// Returns the physoffset of the enclave.
/// We expect the handle to be valid, and the virtaddr to exist in segments.
int get_physoffset_enclave(
    enclave_handle_t handle,
    usize* phys_offset);
/// Sets up access rights and conf|share for the segment.
int mprotect_enclave(
    enclave_handle_t handle,
    usize vstart,
    usize size,
    memory_access_right_t flags,
    enclave_segment_type_t tpe);
/// Register the trap bitmap for the enclave.
int set_traps(enclave_handle_t handle, usize traps);
/// Register the core map for the enclave.
int set_cores(enclave_handle_t handle, usize core_map);
/// Register the perm for the enclave.
int set_perm(enclave_handle_t handle, usize perm);
/// Register the switch_type for the enclave.
int set_switch(enclave_handle_t handle, usize sw);
/// Set the entry point on a core.
int set_entry_on_core(
    enclave_handle_t handle,
    usize core,
    usize cr3,
    usize rip,
    usize rsp);
/// Commits the enclave. This is where the capability operations are done.
int commit_enclave(enclave_handle_t handle);
/// Implements the transition into an enclave.
int switch_enclave(enclave_handle_t handle, void* args);
/// Delete the enclave and revoke the capabilities.
int delete_enclave(enclave_handle_t handle);
/// For debugging purposes, sets the phys_addr for virt_addr.
int debug_addr(usize virt_addr, usize* phys_addr);

#endif /*__SRC_ENCLAVES_H__*/
