#include "back_kvm.h"
#include "common.h"
#include "common_log.h"
#include "../backend.h"
#include "contalloc_driver.h"
#include "sdk_tyche.h"
#include "tyche_driver.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

// ———————————————————————————— Helper functions ———————————————————————————— //

static void ar_to_kvm_segment(struct kvm_segment* var, uint32_t ar)
{ 
  var->type = (ar & 15);
  var->s = (ar >> 4) & 1;
  var->dpl = (ar >> 5) & 1;
  var->present = (ar >> 7) & 1;
  var->avl = (ar >> 12) & 1;
  var->l = (ar >> 13) & 1;
  var->db = (ar >> 14) & 1;
  var->g = (ar >> 15) & 1;
  // TODO not sure;
  var->unusable = (ar >> 16);

  /// Model to compute from ar to kvm_segment.
  /*ar = var->type & 15;
  ar |= (var->s & 1) << 4;
  ar |= (var->dpl & 3) << 5;
  ar |= (var->present & 1) << 7;
  ar |= (var->avl & 1) << 12;
  ar |= (var->l & 1) << 13;
  ar |= (var->db & 1) << 14;
  ar |= (var->g & 1) << 15;
  ar |= (var->unusable || !var->present) << 16;*/
}

static int default_sregs(struct kvm_sregs* sregs)
{
  if (sregs == NULL)  {
    ERROR("Sregs are null");
    goto failure;
  }
  sregs->cs.selector = 0x0;
  sregs->cs.base = 0x0;
  sregs->cs.limit = 0xffff;
  ar_to_kvm_segment(&(sregs->cs), 0xa09b);
  sregs->ds.selector = 0x0;
  sregs->ds.base = 0x0;
  sregs->ds.limit = 0xffff;
  ar_to_kvm_segment(&(sregs->ds), 0xc093);
  sregs->es.selector = 0x0;
  sregs->es.base = 0x0;
  sregs->es.limit = 0xffff;
  ar_to_kvm_segment(&(sregs->es), 0xc093);
  sregs->fs.selector = 0x0;
  sregs->fs.base = 0x0;
  sregs->fs.limit = 0xffff;
  ar_to_kvm_segment(&(sregs->fs), 0x10000);
  sregs->gs.selector = 0x0;
  sregs->gs.base = 0x0;
  sregs->gs.limit = 0xffff;
  ar_to_kvm_segment(&(sregs->gs), 0x10000);
  sregs->ss.selector = 0x0;
  sregs->ss.base = 0x0;
  sregs->ss.limit = 0xffff;
  ar_to_kvm_segment(&(sregs->ss), 0x14000);
  sregs->ldt.selector = 0x0;
  sregs->ldt.base = 0x0;
  sregs->ldt.limit = 0xffff;
  ar_to_kvm_segment(&(sregs->ldt), 0x10000);
  sregs->tr.selector = 0x0;
  sregs->tr.base = 0x0;
  sregs->tr.limit = 0xff;
  ar_to_kvm_segment(&(sregs->tr), 0x8b);
  sregs->idt.base = 0x0;
  sregs->idt.limit = 0xffff;
  sregs->gdt.base = 0x0;
  sregs->gdt.limit = 0xffff;

  sregs->cr0 = DEFAULT_CR0;
  sregs->cr4 = DEFAULT_CR4;
  sregs->efer = DEFAULT_EFER;
  return SUCCESS;
failure:
  return FAILURE;
}

static int default_regs(struct kvm_regs *regs)
{
  if (regs == NULL) {
    ERROR("Regs are null");
    goto failure;
  }
  regs->rflags = DEFAULT_RFLAGS_INTERRUPTS_OFF;
  //regs->rflags = DEFAULT_RFLAGS_INTERRUPTS_ON;
  return SUCCESS;
failure:
  return FAILURE;
}

static domain_mslot_t* find_mslot(tyche_domain_t *domain, usize vaddr) {
  domain_mslot_t *slot = NULL;
  if (domain == NULL) {
    ERROR("Domain is null");
    goto failure;
  }
  dll_foreach(&(domain->mmaps), slot, list) {
    if ((slot->virtoffset <= vaddr) &&
        ((slot->virtoffset + slot->size) > vaddr)) {
      return slot;
    }
  }
failure:
  return NULL;
}

// —————————————————————————————— Backend API ——————————————————————————————— //

int backend_td_create(tyche_domain_t* domain)
{
  msg_t info = {UNINIT_USIZE, UNINIT_USIZE};
  usize perms_coremap = 0;
  // Open the kvm driver.
  int kvm_fd = open(KVM_DRIVER, O_RDWR);
  if (kvm_fd < 0) {
    ERROR("Unable to open kvm driver");
    goto failure;
  }

  // Create the vm.
  // We encode the perms and the coremap inside the machine type.
  perms_coremap = (domain->perms) << 32 | (domain->core_map);
  domain->handle = ioctl(kvm_fd, KVM_CREATE_VM, perms_coremap);
  if (domain->handle < 0) {
    ERROR("Unable to create a VM!");
    close(kvm_fd);
    goto failure;
  }

  domain->backend.kvm_run_mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
  if (domain->backend.kvm_run_mmap_size < 0) {
    ERROR("Failure to get the vcpu mmap size.");
    close(kvm_fd);
    close(domain->handle);
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
  msg_t info = {0};
  domain_mslot_t *slot = NULL;
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
  dll_foreach(&(domain->mmaps), slot, list) {
    slot->virtoffset = (usize) mmap(NULL, (size_t) slot->size,
      PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, domain->backend.memfd, 0);
    if (((void*)(slot->virtoffset)) == MAP_FAILED) {
      ERROR("Unable to allocate memory for the domain.");
      close(domain->handle);
      close(domain->backend.memfd);
      goto failure;
    }
    info.virtaddr = slot->id;
    if (ioctl(domain->backend.memfd, CONTALLOC_GET_PHYSOFFSET, &info) != SUCCESS) {
      ERROR("Getting physoffset failed!");
      close(domain->handle);
      close(domain->backend.memfd);
      //TODO: munmap?
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
  
  backend_region_t* new_region = NULL;
  domain_mslot_t *slot = NULL;
  uint32_t kvm_flags = KVM_FLAGS_ENCODING_PRESENT;
  if (domain == NULL) {
    ERROR("Nul argument.");
    goto failure;
  }
  slot = find_mslot(domain, vstart);
  if (slot == NULL) {
    ERROR("Invalid vstart address");
    goto failure;
  }
  if ((slot->virtoffset + slot->size) < (vstart + size)) {
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
  
  // KVM region initialization.
  kvm_flags |= ((flags & MEM_WRITE) == 0)? KVM_MEM_READONLY : 0;
  kvm_flags |= (flags << KVM_FLAGS_MEM_ACCESS_RIGHTS_IDX) & KVM_FLAGS_MEM_ACCESS_RIGHTS_MASK;
  kvm_flags |= (tpe << KVM_FLAGS_SEGMENT_TYPE_IDX) & KVM_FLAGS_SEGMENT_TYPE_MASK;
  new_region->kvm_mem.slot = domain->backend.counter_slots++;
  new_region->kvm_mem.userspace_addr = vstart;
  new_region->kvm_mem.memory_size = size;
  new_region->kvm_mem.flags = kvm_flags;
  new_region->kvm_mem.guest_phys_addr = (vstart - slot->virtoffset) + slot->physoffset;
  //TODO: handle the flags? for now just save them.
  new_region->flags = flags;
  new_region->tpe = tpe;

  /// Register the region with kvm.
  if (ioctl(domain->handle, KVM_SET_USER_MEMORY_REGION, &new_region->kvm_mem) != 0) {
    ERROR("Failed to register the kvm mem region");
    goto fail_free;
  }
  /*ERROR("[KVM region %d] uaddr: %llx, gpa: %llx, size: %llx | physoffset: %llx",
      new_region->kvm_mem.slot, new_region->kvm_mem.userspace_addr,
      new_region->kvm_mem.guest_phys_addr, new_region->kvm_mem.memory_size,
      slot->physoffset);*/

  /// Add the region to the list.
  dll_add(&(domain->backend.kvm_regions), new_region, list);

  /// All done!
  return SUCCESS;
fail_free:
  free(new_region);
failure:
  return FAILURE;
}

int backend_td_config(tyche_domain_t* domain, usize config, usize value)
{
 //TODO implement. For the moment it's done directly in KVM. 
 return SUCCESS;
}

int backend_td_create_vcpu(tyche_domain_t* domain, usize core_idx)
{
  struct backend_vcpu_info_t *vcpu = NULL;
  if (domain == NULL) {
    ERROR("Nul argument.");
    goto failure;
  }
  if (core_idx >= MAX_CORES || (domain->core_map & (1ULL << core_idx)) == 0) {
    ERROR("Invalid core index %lld for map 0x%llx", core_idx, domain->core_map);
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
  
  // Create the vpcu.
  vcpu->fd = ioctl(domain->handle, KVM_CREATE_VCPU, vcpu->core_id); 
  if (vcpu->fd < 0) {
    ERROR("Unable to create vcpu for core %lld", core_idx);
    goto free_failure;
  }

  // Allocate its memory region.
  vcpu->kvm_run = mmap(NULL, domain->backend.kvm_run_mmap_size,
      PROT_READ | PROT_WRITE, MAP_SHARED, vcpu->fd, 0);
  if (vcpu->kvm_run == MAP_FAILED) {
    ERROR("Map failed for vcpu on core %lld", core_idx);
    goto close_failure;
  }

  // Add the vcpu to the list.
  dll_add(&(domain->vcpus), vcpu, list);  

  // All done!
  return SUCCESS;
close_failure:
  close(vcpu->fd);
free_failure:
  free(vcpu);
failure:
  return FAILURE;
}

int backend_td_init_vcpu(tyche_domain_t* domain, usize core_idx)
{
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

  if (default_sregs(&(vcpu->sregs)) != SUCCESS) {
    ERROR("Unable configure default sregs.");
    goto failure;
  }
  if (default_regs(&(vcpu->regs)) != SUCCESS) {
    ERROR("Unable to configure default regs");
    goto failure;
  }

  // TODO we need to figure out how to make this work for multiple core.
  // Store the info in the elf?
  vcpu->regs.rip = domain->config.entry;
  vcpu->regs.rsp = domain->config.stack;
  vcpu->sregs.cr3 = domain->config.page_table_root;
  // When read that tells pending interrupts.
  //vcpu->sregs.interrupt_bitmap = ??? TODO ???;

  // Register it with kvm.
  if (ioctl(vcpu->fd, KVM_SET_SREGS, &(vcpu->sregs)) < 0) {
    ERROR("Unable to set the sregs for core %lld", core_idx);
    goto failure;
  }
  if (ioctl(vcpu->fd, KVM_SET_REGS, &(vcpu->regs)) < 0) {
    ERROR("Unable to set the regs for core %lld", core_idx);
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
  //I don't think there is anything to do in the kvm case.
  //Let's keep the hook just in case though.
  return SUCCESS;
failure:
  return FAILURE;
}

int backend_td_vcpu_run(tyche_domain_t* domain, usize core)
{
  int ret = 0;
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

  ret = ioctl(vcpu->fd, KVM_RUN, 0);
  if (ret < 0) {
    ERROR("kvm run failed on core %lld", core);
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
    munmap((void*) vcpu->kvm_run, domain->backend.kvm_run_mmap_size);
    close(vcpu->fd);
    free(vcpu);
  }
  // Regions.
  while(!dll_is_empty(&(domain->backend.kvm_regions))) {
    backend_region_t *region = domain->backend.kvm_regions.head;
    dll_remove(&(domain->backend.kvm_regions), region, list);
    free(region);
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

int backend_create_pipe(tyche_domain_t* domain, usize* id, usize physoffset,
    usize size, memory_access_right_t flags, usize width) {
  int fd = 0;
  msg_create_pipe_t pipe = {0};
  if (domain == NULL || id == NULL || size == 0) {
    goto failure;
  }
  //Abuse the tyche API, create a fake domain and use it to create the pipe.
  fd = open(DOMAIN_DRIVER, O_RDWR);
  if (fd < 0) {
    ERROR("Unable to access the tyche driver.");
    goto failure;
  }
  pipe.id = 0;
  pipe.phys_addr = physoffset;
  pipe.size = size;
  pipe.flags = flags;
  pipe.width = width;
  if (ioctl(fd, TYCHE_CREATE_PIPE, &pipe) != SUCCESS) {
    ERROR("Driver create pipe failed");
    goto fail_close;
  }
  *id = pipe.id;
  close(fd);
  return SUCCESS;
fail_close:
  close(fd);
failure:
  return FAILURE;
}


/// TODO: use get/set msrs api?
int backend_acquire_pipe(tyche_domain_t* domain, domain_mslot_t* slot) {
  struct kvm_userspace_memory_region kvm_mem = {0};
  uint32_t kvm_flags = KVM_FLAGS_ENCODING_PRESENT;
  if (domain == NULL || slot == NULL) {
    goto failure;
  }
  kvm_flags |= ((MEM_WRITE|MEM_READ|MEM_SUPER) << KVM_FLAGS_MEM_ACCESS_RIGHTS_IDX)
    & KVM_FLAGS_MEM_ACCESS_RIGHTS_MASK;
  kvm_flags |= (PIPE <<  KVM_FLAGS_SEGMENT_TYPE_IDX) & KVM_FLAGS_SEGMENT_TYPE_MASK;
  kvm_mem.slot = domain->backend.counter_slots++;
  kvm_mem.userspace_addr = slot->virtoffset;
  kvm_mem.memory_size = slot->size;
  kvm_mem.flags = kvm_flags;
  kvm_mem.guest_phys_addr = slot->physoffset;

  // Register the slot as a region with kvm
  if (ioctl(domain->handle, KVM_SET_USER_MEMORY_REGION, &kvm_mem) != 0) {
    ERROR("Failed to register the kvm mem region.");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}
