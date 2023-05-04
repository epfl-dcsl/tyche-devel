#include <string.h>
#include <sys/ioctl.h> 
#include <sys/mman.h>
#include <sys/errno.h>
#include "driver_ioctl.h"
#include "common.h"


int ioctl_getphysoffset_enclave(
    handle_t handle,
    usize* physoffset)
{
  msg_enclave_info_t info = {0, 0};
  if (physoffset == NULL) {
    ERROR("The physoffset is null.");
    goto failure;
  }
  if (ioctl(handle, TYCHE_ENCLAVE_GET_PHYSOFFSET, &info) != SUCCESS) {
    ERROR("Failed to read the physoffset for enclave %d", handle);
    goto failure;
  }
  *physoffset = info.physoffset;
  return SUCCESS;
failure:
  return FAILURE;
}

int ioctl_commit_enclave(
    handle_t handle,
    usize cr3,
    usize entry,
    usize stack)
{
  msg_enclave_commit_t commit = {stack, entry, cr3};
  if (ioctl(handle, TYCHE_ENCLAVE_COMMIT, &commit) != SUCCESS) {
    ERROR("Failed to commit enclave %d.", handle);
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int ioctl_mprotect_enclave(
    handle_t handle,
    usize vstart,
    usize size,
    memory_access_right_t flags,
    enclave_segment_type_t tpe)
{
  msg_enclave_mprotect_t mprotect = {vstart, size, flags, tpe};
  if (ioctl(handle, TYCHE_ENCLAVE_MPROTECT, &mprotect) != SUCCESS) {
    ERROR("Failed to mprotect region %llx -- %llx for enclave %d", vstart, vstart + size, handle);
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

int ioctl_switch_enclave(handle_t handle, void* args)
{
  msg_enclave_switch_t transition = {args};
  if (ioctl(handle, TYCHE_TRANSITION, &transition) != SUCCESS) {
    ERROR("ioctl failed to switch to %lld", handle);
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}
