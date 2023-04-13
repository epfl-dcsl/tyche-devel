#include <sys/ioctl.h> 
#include <sys/mman.h>
#include <sys/errno.h>
#include "driver_ioctl.h"
#include "common.h"

int ioctl_create_enclave(int driver_fd, enclave_handle_t* handle)
{
  msg_enclave_info_t info = {0, 0};
  if (handle == NULL) {
    ERROR("The provided handle is null.");
    goto failure;
  }
  if (ioctl(driver_fd, TYCHE_ENCLAVE_CREATE, &info) != SUCCESS) {
    ERROR("Failed to create an enclave.");
    goto failure;
  }
  *handle = info.handle;
  return SUCCESS;
failure:
  return FAILURE;
}

int ioctl_getphysoffset_enclave(
    int driver_fd,
    enclave_handle_t handle,
    usize virtoffset,
    usize* physoffset)
{
  msg_enclave_info_t info = {handle, virtoffset, 0};
  if (physoffset == NULL) {
    ERROR("The physoffset is null.");
    goto failure;
  }
  if (ioctl(driver_fd, TYCHE_ENCLAVE_GET_PHYSOFFSET, &info) != SUCCESS) {
    ERROR("Failed to read the physoffset for enclave %lld", handle);
    goto failure;
  }
  *physoffset = info.physoffset;
  return SUCCESS;
failure:
  return FAILURE;
}

int ioctl_commit_enclave(
    int driver_fd,
    enclave_handle_t handle,
    usize cr3,
    usize entry,
    usize stack)
{
  msg_enclave_commit_t commit = {handle, stack, entry, cr3};
  if (ioctl(driver_fd, TYCHE_ENCLAVE_COMMIT, &commit) != SUCCESS) {
    ERROR("Failed to commit enclave %lld.", handle);
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int ioctl_mprotect_enclave(
    int driver_fd,
    enclave_handle_t handle,
    usize vstart,
    usize size,
    memory_access_right_t flags,
    enclave_segment_type_t tpe)
{
  msg_enclave_mprotect_t mprotect = {handle, vstart, size, flags, tpe};
  if (ioctl(driver_fd, TYCHE_ENCLAVE_MPROTECT, &mprotect) != SUCCESS) {
    ERROR("Failed to mprotect region %llx -- %llx for enclave %lld", vstart, vstart + size, handle);
    goto failure;
  }
  DEBUG("mprotect %llx -- %llx [%llx:%llx]",
      mprotect.start, mprotect.start + mprotect.size,
      mprotect.flags, mprotect.tpe);
  return SUCCESS;
failure:
  return FAILURE;
}

int ioctl_delete_enclave(int driver_fd, enclave_handle_t handle)
{
  msg_enclave_info_t info = {handle, 0};

  if (ioctl(driver_fd, TYCHE_ENCLAVE_DELETE, &info) != SUCCESS) {
    ERROR("Failed to delete enclave %lld.", handle);
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int ioctl_mmap(int driver_fd, enclave_handle_t handle, usize size, usize* virtoffset)
{
  void* result = NULL;
  if (virtoffset == NULL) {
    ERROR("The virtoffset variable is null");
    goto failure;
  }
  result = mmap(NULL, (size_t) size, PROT_READ|PROT_WRITE,
      /*MAP_ANONYMOUS|MAP_PRIVATE|MAP_POPULATE*/ MAP_PRIVATE|MAP_POPULATE, driver_fd, 0);
  if (result == MAP_FAILED) {
    ERROR("MMap to the driver failed %d", errno);
    goto failure;
  }
  *virtoffset = (usize) result;
  DEBUG("mmap success for %lld, address %llx", handle, result);
  return SUCCESS;
failure:
  return FAILURE;
}

int ioctl_switch_enclave(int driver_fd, enclave_handle_t handle, void* args)
{
  msg_enclave_switch_t transition = {handle, args};
  if (ioctl(driver_fd, TYCHE_TRANSITION, &transition) != SUCCESS) {
    ERROR("ioctl failed to switch to %lld", handle);
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int ioctl_debug_addr(int driver_fd, usize virtaddr, usize* physaddr)
{
  msg_enclave_info_t info = {0, virtaddr, 0};
  if (physaddr == NULL) {
    ERROR("Provided physaddr is null");
    goto failure;
  }
  if (ioctl(driver_fd, TYCHE_DEBUG_ADDR, &info) != SUCCESS) {
    ERROR("ioctl failed to debug_addr %llx", virtaddr);
    goto failure;
  }
  *physaddr = info.physoffset;
  return SUCCESS;
failure:
  return FAILURE;
}
