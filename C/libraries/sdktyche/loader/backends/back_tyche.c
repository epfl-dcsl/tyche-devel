#include "common.h"
#include "../backend.h"
#include "tyche_driver.h"

#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h> 
// ——————————————————————————— Local definitions ———————————————————————————— //

#define DOMAIN_DRIVER ("/dev/tyche")

// ————————————————————————— Local helper functions ————————————————————————— //


static int ioctl_mmap(handle_t handle, usize size, usize* virtoffset)
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
      MAP_SHARED|MAP_POPUL  // Open the driver.
  domain->handle = open(DOMAIN_DRIVER, O_RDWR);
  if (domain->handle < 0) {
    ERROR("Unable to create an domain with open %s", DOMAIN_DRIVER);
    goto failure;
  }

  // Mmap the size of memory we need.
  if (ioctl_mmap(
        domain->handle,
        domain->map.size,
        &(domain->map.virtoffset)) != SUCCESS) {
    goto failure;
  }
  
  // Get the physoffset.
  if (ioctl_getphysoffset(
        domain->handle,
        &(domain->map.physoffset)) != SUCCESS) {
    goto failure;
  }
#endif /* RUN_WITH_KVM */
ATE,
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

static int ioctl_getphysoffset(handle_t handle, usize* physoffset)
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

static int ioctl_mprotect(handle_t handle, usize vstart, usize size, 
    memory_access_right_t flags, segment_type_t tpe)
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

// —————————————————————————————— Backend API ——————————————————————————————— //


int backend_td_create(tyche_domain_t* domain)
{
  if (domain == NULL) {
    ERROR("Null argument.");
    goto failure;
  }
  // Open the driver.
  domain->handle = open(DOMAIN_DRIVER, O_RDWR);
  if (domain->handle < 0) {
    ERROR("Unable to create an domain with open %s", DOMAIN_DRIVER);
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int backend_td_alloc_mem(tyche_domain_t* domain)
{
  if (domain == NULL) {
    ERROR("Null argument.");
    goto failure;
  }
  // Mmap the size of memory we need.
  if (ioctl_mmap(
        domain->handle,
        domain->map.size,
        &(domain->map.virtoffset)) != SUCCESS) {
    goto failure;
  }
  
  // Get the physoffset.
  if (ioctl_getphysoffset(
        domain->handle,
        &(domain->map.physoffset)) != SUCCESS) {
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int backend_td_register_region(
    tyche_domain_t* domain,
    usize vstart,
    usize size,
    memory_access_right_t flags,
    segment_type_t tpe) {
  if (domain == NULL) {
    ERROR("Nul argument");
    return FAILURE;
  }
  return ioctl_mprotect(domain->handle, vstart, size, flags, tpe);
}
