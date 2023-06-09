#ifndef __INCLUDE_TYCHE_ENCLAVE_H__
#define __INCLUDE_TYCHE_ENCLAVE_H__

#ifdef _IN_MODULE
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#endif

#include "tyche_capabilities_types.h"

// ———————————————————— Constants Defined in the Module ————————————————————— //
#define TE_READ ((uint64_t)MEM_READ)
#define TE_WRITE ((uint64_t)MEM_WRITE)
#define TE_EXEC ((uint64_t)MEM_EXEC)
#define TE_SUPER ((uint64_t)MEM_SUPER)
#define TE_DEFAULT ((uint64_t)(TE_READ | TE_WRITE | TE_EXEC))

// —————————————————————— Types Exposed by the Library —————————————————————— //
typedef struct file* enclave_handle_t;

typedef enum enclave_segment_type_t {
  SHARED = 0,
  CONFIDENTIAL = 1,
} enclave_segment_type_t;

// ———————————————————————————————— Messages ———————————————————————————————— //

/// Default message used to communicate with the driver.
/// create_enclave sets the handle;
/// get_physoffset expects the handle to be valid and sets the physoffset.
typedef struct {
  usize virtaddr;
  usize physoffset;
} msg_enclave_info_t;

/// Message type to add a new region.
typedef struct {
  /// Start virtual address. Must be page aligned and within the mmaped region.
  usize start;

  /// Must be page aligned, greater than start, and within the mmaped region.
  usize size;

  /// Access right (RWXU) for this region.
  memory_access_right_t flags;

  /// Type of mapping: Confidential or Shared.
  enclave_segment_type_t tpe;
} msg_enclave_mprotect_t;

/// Structure of the commit message.
typedef struct {
  /// The pointer to the stack.
  usize stack;

  /// The entry point.
  usize entry;

  /// The page tables.
  usize page_tables;
} msg_enclave_commit_t;

/// Structure to perform a transition.
typedef struct {
  /// The args, will end up in r11 on x86.
  void* args;
} msg_enclave_switch_t;

// ——————————————————————————— Tyche Enclave IOCTL API —————————————————————— //
// @deprecated, use open.
//#define TYCHE_ENCLAVE_CREATE _IOR('a', 'b', msg_enclave_info_t*)
#define TYCHE_ENCLAVE_GET_PHYSOFFSET _IOR('a', 'c', msg_enclave_info_t*)
#define TYCHE_ENCLAVE_COMMIT _IOWR('a', 'd', msg_enclave_commit_t*)
#define TYCHE_ENCLAVE_MPROTECT _IOW('a', 'e', msg_enclave_mprotect_t*)
#define TYCHE_TRANSITION _IOR('a', 'f', msg_enclave_switch_t*)
// @deprecate, use close
//#define TYCHE_ENCLAVE_DELETE _IOR('a', 'g', msg_enclave_info_t*)
#define TYCHE_DEBUG_ADDR _IOWR('a', 'h', msg_enclave_info_t*)

#endif
