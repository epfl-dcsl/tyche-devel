#include <string.h>
#include <sys/ioctl.h> 
#include <sys/mman.h>
#include <sys/errno.h>
#include "driver_ioctl.h"
#include "common.h"


int ioctl_getphysoffset(
    handle_t handle,
    usize* physoffset)
{
  msg_info_t info = {0, 0};
  if (physoffset == NULL) {
    ERROR("The physoffset is null.");
    goto failure;
  }
  if (ioctl(handle, TYCHE_GET_PHYSOFFSET, &info) != SUCCESS) {
    ERROR("Failed to read the physoffset for domain %d", handle);
    goto failure;
  }
  *physoffset = info.physoffset;
  return SUCCESS;
failure:
  return FAILURE;
}

int ioctl_commit(handle_t handle)
{
  if (ioctl(handle, TYCHE_COMMIT, NULL) != SUCCESS) {
    ERROR("Failed to commit domain %d.", handle);
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int ioctl_set_traps(handle_t handle, usize traps) {
  msg_set_perm_t perm = {traps}; 
  if (ioctl(handle, TYCHE_SET_TRAPS, &perm) != SUCCESS) {
      ERROR("Failed to set traps for the domain %d", handle);
      goto failure;
    }
  return SUCCESS;
failure:
  return FAILURE;
}

int ioctl_set_cores(handle_t handle, usize cores) {
  msg_set_perm_t perm = {cores}; 
  if (ioctl(handle, TYCHE_SET_CORES, &perm) != SUCCESS) {
      ERROR("Failed to set cores for the domain %d", handle);
      goto failure;
    }
  return SUCCESS;
failure:
  return FAILURE;
}

int ioctl_set_perms(handle_t handle, usize perms) {
  msg_set_perm_t perm = {perms}; 
  if (ioctl(handle, TYCHE_SET_PERM, &perm) != SUCCESS) {
      ERROR("Failed to set perms for the domain %d", handle);
      goto failure;
    }
  return SUCCESS;
failure:
  return FAILURE;
}

int ioctl_set_switch(handle_t handle, usize sw) {
  msg_set_perm_t perm = {sw}; 
  if (ioctl(handle, TYCHE_SET_SWITCH, &perm) != SUCCESS) {
      ERROR("Failed to set switch for the domain %d", handle);
      goto failure;
    }
  return SUCCESS;
failure:
  return FAILURE;
}

int ioctl_set_entry_on_core(
    handle_t handle,
    usize core,
    usize cr3,
    usize rip,
    usize rsp)
{
  msg_entry_on_core_t entry = {.core = core, .stack = rsp, .entry = rip, .page_tables = cr3};
  if (ioctl(handle, TYCHE_SET_ENTRY_POINT, &entry) != SUCCESS) {
      ERROR("Failed to set entry for the domain %d", handle);
      goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int ioctl_mprotect(
    handle_t handle,
    usize vstart,
    usize size,
    memory_access_right_t flags,
    segment_type_t tpe)
{
  msg_mprotect_t mprotect = {vstart, size, flags, tpe};
  if (ioctl(handle, TYCHE_MPROTECT, &mprotect) != SUCCESS) {
    ERROR("Failed to mprotect region %llx -- %llx for domain %d", vstart, vstart + size, handle);
    goto failure;
  }
  DEBUG("mprotect %llx -- %llx [%llx:%llx]",
      mprotect.start, mprotect.start + mprotect.size,
      mprotect.flags, mprotect.tpe);
  return SUCCESS;
failure:
  return FAILURE;
}

int ioctl_mmap(handle_t handle, usize size, usize* virtoffset)
{
  void* result = NULL;
  if (virtoffset == NULL) {
    ERROR("The virtoffset variable is null");
    goto failure;
  }
  result = mmap(
      NULL,
      (size_t) size,
      PROT_READ|PROT_WRITE,
      MAP_SHARED|MAP_POPULATE,
      handle,
      0);
  if (result == MAP_FAILED) {
    ERROR("MMap to the driver failed %s", strerror(errno));
    goto failure;
  }
  *virtoffset = (usize) result;
  DEBUG("mmap success for %d, address %llx", handle, result);
  return SUCCESS;
failure:
  return FAILURE;
}

int ioctl_switch(handle_t handle, void* args)
{
  msg_switch_t transition = {args};
  if (ioctl(handle, TYCHE_TRANSITION, &transition) != SUCCESS) {
    ERROR("ioctl failed to switch to %lld", handle);
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}
