#include "common.h"
#include "../backend.h"
#include "tyche_driver.h"
#include "back_tyche.h"
#include "tyche_api.h"
#include "sdk_tyche.h"

#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h> 
#include <unistd.h>
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


int backend_td_config_vm(tyche_domain_t* domain, usize config, usize value)
{
  msg_set_perm_t msg = {config, value};
  if (domain == NULL) {
    ERROR("Nul argument");
    goto failure;
  }
  // Check the config is valid.
  if (config < 0 || config >= TYCHE_NR_CONFIGS) {
    ERROR("Invalid config number: %lld", config);
    goto failure;
  }
  
  if (ioctl(domain->handle, TYCHE_SET_DOMAIN_CONFIGURATION, &msg) != SUCCESS) {
    ERROR("Failed to set domain configuration %lld to value %llx", msg.idx, msg.value);
    goto failure;
  }
  // All done.
  return SUCCESS;
failure:
  return FAILURE;
}

int backend_td_create_vcpu(tyche_domain_t* domain, usize core_idx)
{
  struct backend_vcpu_info_t * vcpu = NULL;
  if (domain == NULL) {
    ERROR("Nul argument.");
    goto failure;
  }
  if (core_idx >= MAX_CORES || (domain->core_map & (1ULL << core_idx)) == 0) {
    ERROR("Invalid core index.");
    goto failure;
  }
  // Create a vcpu. 
  vcpu = (backend_vcpu_info_t *) malloc(sizeof(backend_vcpu_info_t));
  if (vcpu == NULL) {
    ERROR("Unable to allocate vcpu for core %lld", core_idx);
    goto failure;
  }
  memset(vcpu, 0, sizeof(backend_vcpu_info_t));
  dll_init_elem(vcpu, list);
  vcpu->core_id = core_idx; 
 
  // Allocate the core context.
  if (ioctl(domain->handle, TYCHE_ALLOC_CONTEXT, core_idx) != SUCCESS) {
    ERROR("Failed to allocate core context %lld.", core_idx);
    goto failure_free;
  }

  // Add the vcpu to the list.
  dll_add(&(domain->vcpus), vcpu, list);

  // All done!
  return SUCCESS;
failure_free:
  free(vcpu);
failure:
  return FAILURE;
}

int backend_td_init_vcpu(tyche_domain_t* domain, usize core_idx)
{
  msg_entry_on_core_t msg = {0};
  struct backend_vcpu_info_t* vcpu = NULL;
  if (domain == NULL) {
    ERROR("Nul argument.");
    goto failure;
  }
  dll_foreach(&(domain->vcpus), vcpu, list) {
    if (vcpu->core_id == core_idx) {
      break;
    }
  }
  // Unable to find it.
  if (vcpu == NULL) {
    ERROR("Unable to find vcpu for core %lld. Call create_vcpu first!", core_idx);
    goto failure;
  }
  //TODO: we need to figure that out.
  //The elf binary so far was only configured to support one core.
  // We thus have a single entry point and stack...
  vcpu->stack = domain->config.stack;
  vcpu->rip = domain->config.entry;
  vcpu->cr3 = domain->config.page_table_root;
  
  msg.core = vcpu->core_id;
  msg.stack = vcpu->stack;
  msg.entry = vcpu->rip;
  msg.page_tables = vcpu->cr3;
  if (ioctl(domain->handle, TYCHE_SET_ENTRY_POINT, &msg) != SUCCESS) {
    ERROR("Unable to set entry point with driver for core %lld", core_idx);
    goto failure;
  }
  // All done!
  return SUCCESS;
failure:
  return FAILURE;
}


int backend_td_commit(tyche_domain_t* domain)
{
  if (domain == NULL) {
    ERROR("Nul argument.");
    goto failure;
  }
  if (ioctl(domain->handle, TYCHE_COMMIT, NULL) != SUCCESS) {
    ERROR("Unable to commit the domain.");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int backend_td_vcpu_run(tyche_domain_t* domain, usize core)
{
  struct backend_vcpu_info_t *vcpu = NULL;
  if (domain == NULL) {
    ERROR("Nul argument");
    goto failure;
  }
  dll_foreach(&(domain->vcpus), vcpu, list) {
    if (vcpu->core_id == core) {
      break;
    }
  }
  // Unable to find it.
  if (vcpu == NULL) {
    ERROR("Unable to find vcpu for core %lld. Call create_vcpu first!", core);
    goto failure;
  }

  if (ioctl(domain->handle, TYCHE_TRANSITION, core) != SUCCESS) {
    ERROR("Failure to run on core %lld", core);
    goto failure;
  }
  //All done!
  return SUCCESS;
failure:
  return FAILURE;
}

int backend_td_delete(tyche_domain_t* domain)
{
  if (domain == NULL) {
    ERROR("Nul argument.");
    goto failure;
  }
  while(!dll_is_empty(&(domain->vcpus))) {
    struct backend_vcpu_info_t *vcpu = domain->vcpus.head;
    dll_remove(&(domain->vcpus), vcpu, list);
    free(vcpu);
  }
  // Unmap the domain.
  munmap((void*) domain->map.virtoffset, domain->map.size); 
  close(domain->handle);
  return SUCCESS;
failure:
  return FAILURE;

}
