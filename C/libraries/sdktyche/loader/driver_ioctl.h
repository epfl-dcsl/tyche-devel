#pragma once

#include "sdk_tyche_types.h"

#ifdef RUN_WITH_KVM
#include "contalloc_driver.h"
#else
#include "tyche_driver.h"
#endif
// ——————————————————————————————— Functions ———————————————————————————————— //

int getphysoffset(handle_t handle, usize* physoffset);
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
int ioctl_alloc_core_context(handle_t handle, usize core);
int ioctl_set_traps(handle_t handle, usize traps);
int ioctl_set_perms(handle_t handle, usize perms);
int ioctl_set_switch(handle_t handle, usize sw);
int ioctl_set_entry_on_core(
    handle_t handle,
    usize core,
    usize cr3,
    usize rip,
    usize rsp);
