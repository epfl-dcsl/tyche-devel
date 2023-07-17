#ifndef __LOADER_DRIVER_IOCTL_H__
#define __LOADER_DRIVER_IOCTL_H__

#include "enclave_loader.h"
#include "tyche_enclave.h"

// ——————————————————————————————— Functions ———————————————————————————————— //

int ioctl_getphysoffset_enclave(handle_t handle, usize* physoffset);
int ioctl_commit_enclave(handle_t handle);
int ioctl_mprotect_enclave(
    handle_t handle,
    usize vstart,
    usize size,
    memory_access_right_t flags,
    enclave_segment_type_t tpe);
int ioctl_mmap(handle_t handle, usize size, usize* virtoffset);
int ioctl_switch_enclave(handle_t handle, void* args);
int ioctl_set_cores(handle_t handle, usize cores);
int ioctl_set_traps(handle_t handle, usize traps);
int ioctl_set_perms(handle_t handle, usize perms);
int ioctl_set_switch(handle_t handle, usize sw);
int ioctl_set_entry_on_core(
    handle_t handle,
    usize core,
    usize cr3,
    usize rip,
    usize rsp);
#endif /*__LOADER_DRIVER_IOCTL_H__*/
