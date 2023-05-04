#ifndef __LOADER_DRIVER_IOCTL_H__
#define __LOADER_DRIVER_IOCTL_H__

#include "enclave_loader.h"
#include "tyche_enclave.h"

// ——————————————————————————————— Functions ———————————————————————————————— //

int ioctl_getphysoffset_enclave(handle_t handle, usize* physoffset);
int ioctl_commit_enclave(
    handle_t handle,
    usize cr3,
    usize entry,
    usize stack);
int ioctl_mprotect_enclave(
    handle_t handle,
    usize vstart,
    usize size,
    memory_access_right_t flags,
    enclave_segment_type_t tpe);
int ioctl_mmap(handle_t handle, usize size, usize* virtoffset);
int ioctl_switch_enclave(handle_t handle, void* args);
#endif /*__LOADER_DRIVER_IOCTL_H__*/
