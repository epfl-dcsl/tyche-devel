#ifndef __LOADER_DRIVER_IOCTL_H__
#define __LOADER_DRIVER_IOCTL_H__

#include "tyche_enclave.h"

// ——————————————————————————————— Functions ———————————————————————————————— //

int ioctl_create_enclave(int driver_fd, enclave_handle_t* handle);
int ioctl_getphysoffset_enclave(
    int driver_fd,
    enclave_handle_t handle,
    usize virtoffset,
    usize* physoffset);
int ioctl_commit_enclave(
    int driver_fd,
    enclave_handle_t handle,
    usize cr3,
    usize entry,
    usize stack);
int ioctl_mprotect_enclave(
    int driver_fd,
    enclave_handle_t handle,
    usize vstart,
    usize size,
    memory_access_right_t flags,
    enclave_segment_type_t tpe);
int ioctl_delete_enclave(int driver_fd, enclave_handle_t handle);
int ioctl_mmap(int driver_fd, enclave_handle_t handle, usize size, usize* virtoffset);
int ioctl_switch_enclave(int driver_fd, enclave_handle_t handle, void* args);
#endif /*__LOADER_DRIVER_IOCTL_H__*/
