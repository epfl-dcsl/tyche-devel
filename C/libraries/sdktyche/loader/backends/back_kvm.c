#include "common.h"
#include "../backend.h"
#include "contalloc_driver.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>

// ———————————————————————— Backend specific defines ———————————————————————— //

#define KVM_DRIVER ("/dev/kvm")
#define CONTALLOC_DRIVER ("/dev/contalloc")

// —————————————————————————————— Backend API ——————————————————————————————— //


int backend_td_create(tyche_domain_t* domain)
{
  msg_info_t info = {UNINIT_USIZE, UNINIT_USIZE};
  // Open the kvm driver.
  int kvm_fd = open(KVM_DRIVER, O_RDWR);
  if (kvm_fd < 0) {
    ERROR("Unable to open kvm driver");
    goto failure;
  }

  // Create the vm.
  domain->handle = ioctl(kvm_fd, KVM_CREATE_VM, 0); 
  if (domain->handle < 0) {
    ERROR("Unable to create a VM!");
    close(kvm_fd);
    goto failure;
  }
  // Don't need it anymore?
  close(kvm_fd);
  return SUCCESS;
failure:
  return FAILURE;
}

int backend_td_alloc_mem(tyche_domain_t* domain)
{
  if (domain == NULL) {
    ERROR("Nul argument.");
    goto failure;
  }
  // Call contalloc driver to get contiguous memory.
  domain->backend.memfd = open(CONTALLOC_DRIVER, O_RDWR);
  if (domain->backend.memfd < 0) {
    ERROR("Unable to open the contalloc driver.");
    close(domain->handle);
    goto failure;
  }
  domain->map.virtoffset = (usize) mmap(NULL, (size_t) domain->map.size,
      PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, domain->backend.memfd, 0);
  if (((void*)(domain->map.virtoffset)) == MAP_FAILED) {
    ERROR("Unable to allocate memory for the domain.");
    close(domain->handle);
    close(domain->backend.memfd);
    goto failure;
  }

  if (ioctl(domain->backend.memfd, CONTALLOC_GET_PHYSOFFSET, &info) != SUCCESS) {
    ERROR("Getting physoffset failed!");
    close(domain->handle);
    close(domain->backend.memfd);
    //TODO: munmap?
    goto failure;
  }
  domain->map.physoffset = info.physoffset; 
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
  
  backend_region_t* new_region = NULL;
  if (domain == NULL) {
    ERROR("Nul argument.");
    goto failure;
  }
  if (domain->virtoffset > vstart) {
    ERROR("Invalid vstart address");
    goto failure;
  }
  if (domain->map.virtoffset + domain->map.size < vstart + size) {
    ERROR("Overflow of region.");
    goto failure;
  } 

  new_region = (backend_region_t*) malloc(sizeof(backend_region_t));
  if (new_region == NULL) {
    ERROR("Unable to allocate a new region.");
    goto failure;
  }
  memset(new_region, 0, sizeof(backend_region_t));
  dll_init_elem(new_region, list);
  new_region->kvm_mem.slot = domain->backend.counter_slots++;
  new_region->kvm_mem.userspace_addr = vstart;
  new_region->kvm_mem.memory_size = size;
  new_region->kvm_mem.guest_phys_addr = (vstart - domain->map.virtoffset);
  //TODO: handle the flags? for now just save them.
  new_region->flags = flags;
  new_region->tpe = tpe;

  /// Register the region with kvm.
  if (ioctl(domain->handle, KVM_SET_USER_MEMORY_REGION, &new_region->kvm_mem) != 0) {
    ERROR("Failed to register the kvm mem region");
    goto fail_free;
  }

  /// Add the region to the list.
  dll_add(&(domain->backend.kvm_regions), new_region, list);

  /// All done!
  return SUCCESS;
fail_free:
  free(new_region);
failure:
  return FAILURE;
}
