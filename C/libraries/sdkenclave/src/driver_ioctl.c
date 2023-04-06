#include <sys/ioctl.h> 
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

int ioctl_getphysoffset_enclave(int driver_fd, enclave_handle_t handle, usize* physoffset)
{
  msg_enclave_info_t info = {handle, 0};
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
  return failure;
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
