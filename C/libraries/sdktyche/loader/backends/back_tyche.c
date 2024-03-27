#include "back_tyche.h"
#include "common.h"
#include "common_log.h"
#include "../backend.h"
#include "tyche_driver.h"
#include "tyche_api.h"
#include "sdk_tyche.h"
#include "tyche_register_map.h"

#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h> 
#include <unistd.h>
#include <stdlib.h>

#if defined(CONFIG_X86) || defined(__x86_64__)
#include <asm/vmx.h>
#endif
// ——————————————————————————— Local definitions ———————————————————————————— //

#define DOMAIN_DRIVER ("/dev/tyche")

// ————————————————————————— Local helper functions ————————————————————————— //

static int ioctl_mprotect(handle_t handle, usize vstart, usize size, 
    memory_access_right_t flags, segment_type_t tpe)
{
  msg_mprotect_t mprotect = {vstart, size, flags, tpe};
  if (ioctl(handle, TYCHE_MPROTECT, &mprotect) != SUCCESS) {
    ERROR("Failed to mprotect region %llx -- %llx for domain %d", vstart, vstart + size, handle);
    goto failure;
  }
  /*DEBUG("mprotect %llx -- %llx [0x%x:0x%x]",
      mprotect.start, mprotect.start + mprotect.size,
      mprotect.flags, mprotect.tpe);*/
  return SUCCESS;
failure:
  return FAILURE;
}

static int default_vcpu(tyche_domain_t* domain, backend_vcpu_info_t* vcpu) {
  msg_set_perm_t msg = {0};
  if (domain == NULL) {
    ERROR("The provided domain is null");
    goto failure;
  }
  if (vcpu == NULL) {
    ERROR("The provided vcpu is null");
    goto failure;
  }
  // Set the bitmap for exceptions.
  msg.core = vcpu->core_id;
  msg.idx = EXCEPTION_BITMAP;
  msg.value = ~(domain->traps);
  if (ioctl(domain->handle, TYCHE_SET_DOMAIN_CORE_CONFIG, &msg) != SUCCESS) {
    ERROR("Unable to set bitmap.");
    goto failure;
  } 
  // Set the cr0.
  msg.idx = GUEST_CR0;
  msg.value = DEFAULT_CR0;
  if (ioctl(domain->handle, TYCHE_SET_DOMAIN_CORE_CONFIG, &msg) != SUCCESS) {
    ERROR("Unable to set cr0 on core %d", vcpu->core_id);
    goto failure;
  }
  msg.idx = GUEST_CR4;
  msg.value = DEFAULT_CR4 | DEFAULT_CR4_EXTRAS;
  if (ioctl(domain->handle, TYCHE_SET_DOMAIN_CORE_CONFIG, &msg) != SUCCESS) {
    ERROR("Unable to set cr4 on core %d", vcpu->core_id);
    goto failure;
  }
  msg.idx = GUEST_IA32_EFER;
  msg.value = DEFAULT_EFER;
  if (ioctl(domain->handle, TYCHE_SET_DOMAIN_CORE_CONFIG, &msg) != SUCCESS) {
    ERROR("Unable to set efer on core %d", vcpu->core_id);
    goto failure;
  }
  msg.idx = GUEST_RFLAGS;
  //With the tyche backend we cannot enable interrupts sadly.
  msg.value = DEFAULT_RFLAGS_INTERRUPTS_OFF;
  if (ioctl(domain->handle, TYCHE_SET_DOMAIN_CORE_CONFIG, &msg) != SUCCESS) {
    ERROR("Unable to set rflags on core %d", vcpu->core_id);
    goto failure;
  }

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
  msg_info_t info = {0};
  domain_mslot_t *slot = NULL;
  if (domain == NULL) {
    ERROR("Null argument.");
    goto failure;
  }

  dll_foreach(&(domain->mmaps), slot, list) {
    slot->virtoffset = (usize) mmap(NULL, (size_t) (slot->size),
      PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, domain->handle, 0);
    if (slot->virtoffset == (usize) MAP_FAILED) {
      ERROR("Unable to map the slot");
      goto failure;
    }
    // Get the physoffset now.
    info.virtaddr = slot->id;
    if (ioctl(domain->handle, TYCHE_GET_PHYSOFFSET, &info) != SUCCESS) {
      ERROR("Failed to read the physoffset for domain %d", domain->handle);
      goto failure;
    }
    slot->physoffset = info.physoffset;
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
    goto failure;
  }
  if (ioctl_mprotect(domain->handle, vstart, size, flags, tpe) != SUCCESS) {
    ERROR("Unable to mprotect region at %llx", vstart);
    goto failure;
  }
  //TODO: should we commit the regions now already?
  return SUCCESS;
failure:
    return FAILURE;
}


int backend_td_config(tyche_domain_t* domain, usize config, usize value)
{
  msg_set_perm_t msg = {0, config, value};
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
  msg_set_perm_t msg = {0};
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

  if (default_vcpu(domain, vcpu) != SUCCESS) {
    ERROR("Unable to configure the default vcpu on core %lld", core_idx);
    goto failure;
  }
  //TODO: we need to figure that out.
  //The elf binary so far was only configured to support one core.
  // We thus have a single entry point and stack...
  vcpu->stack = domain->config.stack;
  vcpu->rip = domain->config.entry;
  vcpu->cr3 = domain->config.page_table_root;
  
  msg.core = vcpu->core_id;
  // Set the stack.
  msg.idx = REG_GP_RSP;
  msg.value = vcpu->stack; 
  if (ioctl(domain->handle, TYCHE_SET_DOMAIN_CORE_CONFIG, &msg) != SUCCESS) {
    ERROR("Unable to set the stack for the vcpu.");
    goto failure;
  }
  // Set the rip.
  msg.idx = REG_GP_RIP;
  msg.value = vcpu->rip; 
  if (ioctl(domain->handle, TYCHE_SET_DOMAIN_CORE_CONFIG, &msg) != SUCCESS) {
    ERROR("Unable to set the stack for the vcpu.");
    goto failure;
  }
  // Set the rip.
  msg.idx = REG_GP_CR3;
  msg.value = vcpu->cr3; 
  if (ioctl(domain->handle, TYCHE_SET_DOMAIN_CORE_CONFIG, &msg) != SUCCESS) {
    ERROR("Unable to set the stack for the vcpu.");
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
  // Unmap the domain's memory slots.
  while(!dll_is_empty(&(domain->mmaps))) {
    domain_mslot_t *slot = domain->mmaps.head;
    dll_remove(&(domain->mmaps), slot, list);
    munmap((void*)(slot->virtoffset), slot->size);
    free(slot);
  }
  close(domain->handle);
  return SUCCESS;
failure:
  return FAILURE;

}
