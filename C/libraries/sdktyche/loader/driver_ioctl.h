#pragma once

#include "sdk_tyche_types.h"
#include "tyche_driver.h"
// ——————————————————————————————— Functions ———————————————————————————————— //

int ioctl_getphysoffset(handle_t handle, usize* physoffset);
int ioctl_commit(handle_t handle);
int ioctl_mprotect(
    handle_t handle,
    usize vstart,
    usize size,
    memory_access_right_t flags,
    segment_type_t tpe);
int ioctl_mmap(handle_t handle, usize size, usize* virtoffset);
int ioctl_switch(handle_t handle, void* args);
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
