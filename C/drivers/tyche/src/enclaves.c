#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/mm_types.h>
#include <asm/io.h>
#include <linux/fs.h>

#include "common.h"
#include "enclaves.h"
#include "dbg_addresses.h"
#include "tyche_capabilities.h"
#include "tyche_capabilities_types.h"
#include "tyche_enclave.h"

// ———————————————————————————————— Globals ————————————————————————————————— //

static dll_list(enclave_t, enclaves);

// ———————————————————————————— Helper Functions ———————————————————————————— //

static enclave_t* find_enclave(enclave_handle_t handle)
{
  enclave_t* encl = NULL;
  dll_foreach((&enclaves), encl, list) {
    if (encl->handle == handle) {
      break;
    }
  }
  if (encl == NULL) {
    goto failure;
  }
  if (encl->pid != current->pid) {
    ERROR("Attempt to access enclave %p from wrong pid", handle);
    ERROR("Expected pid: %d, got: %d", encl->pid, current->pid);
    goto failure;
  }
  return encl;
failure:
  return NULL;
}


// ——————————————————————————————— Functions ———————————————————————————————— //

void init_enclaves(void)
{
  dll_init_list((&enclaves));
  init_capabilities();
}


int create_enclave(enclave_handle_t handle)
{
  enclave_t* encl = NULL;
  encl = find_enclave(handle);
  if (encl != NULL) {
    ERROR("The enclave with handle %p already exists.", handle);
    goto failure;
  }
  encl = kmalloc(sizeof(enclave_t), GFP_KERNEL);
  if (encl == NULL) {
    ERROR("Failed to allocate a new enclave_t structure.");
    goto failure;
  }
  // Set up the structure.
  encl->pid = current->pid;
  encl->handle = handle;
  encl->domain_id = UNINIT_DOM_ID;
  encl->phys_start = UNINIT_USIZE;
  encl->virt_start = UNINIT_USIZE;
  encl->size = UNINIT_USIZE;
  // Init bitmaps. 
  encl->perm = 0;
  encl->cores = 0;
  encl->traps = 0;
  // Setup the entries.
  encl->entries.size = 0;
  encl->entries.entries = NULL;
  dll_init_list(&(encl->segments));
  dll_init_elem(encl, list);

  // Add the enclave to the list.
  dll_add((&enclaves), encl, list);
  LOG("A new enclave was added to the driver with id %p", handle);
  return SUCCESS;
failure:
  return FAILURE;
}

int mmap_segment(enclave_handle_t handle, struct vm_area_struct *vma)
{
  void* allocation = NULL;
  usize size = 0;
  enclave_t* encl = NULL;
  if (vma == NULL) {
    ERROR("The provided vma is null.");
    goto failure;
  }
  // Checks on the vma.
  if (vma->vm_end <= vma->vm_start) {
    ERROR("End is smaller than start");
    goto failure;
  }
  if (vma->vm_start % PAGE_SIZE != 0 || vma->vm_end % PAGE_SIZE != 0) {
    ERROR("End or/and Start is/are not page-aligned.");
    goto failure;
  }
  encl = find_enclave(handle);
  if (encl == NULL) {
    ERROR("Unable to find the right enclave.");
  }
  if (encl->virt_start != UNINIT_USIZE || encl->phys_start != UNINIT_USIZE) {
    ERROR("The enclave has already been initialized.");
    goto failure;
  }

  // Allocate a contiguous memory region.
  size = vma->vm_end - vma->vm_start;
  allocation = alloc_pages_exact(size, GFP_KERNEL); 
  if (allocation == NULL) {
    ERROR("Alloca pages exact failed to allocate the pages.");
    goto failure;
  }
  memset(allocation, 0, size);
  // Prevent pages from being collected.
  for (int i = 0; i < (size/PAGE_SIZE); i++) {
    char* mem = ((char*)allocation) + i * PAGE_SIZE;
    SetPageReserved(virt_to_page((unsigned long)mem));
  }

  DEBUG("The phys address %llx, virt: %llx", (usize) virt_to_phys(allocation), (usize) allocation);
  if (vm_iomap_memory(vma, virt_to_phys(allocation), size)) {
    ERROR("Unable to map the memory...");
    goto fail_free_pages;
  }

  // Set the values inside the enclave structure.
  encl->phys_start = (usize) virt_to_phys(allocation);
  encl->virt_start = (usize) vma->vm_start;
  encl->size = size;
  return SUCCESS;
fail_free_pages:
  free_pages_exact(allocation, size);
failure:
  return FAILURE;
}

int get_physoffset_enclave(
    enclave_handle_t handle,
    usize* phys_offset)
{
  enclave_t* encl = NULL;
  if (phys_offset == NULL) {
    ERROR("The provided phys_offset variable is null.");
    goto failure;
  }
  encl = find_enclave(handle);
  if (encl == NULL) {
    ERROR("The handle %p does not correspond to an enclave.", handle);
    goto failure;
  }
  if (encl->virt_start == UNINIT_USIZE || encl->phys_start == UNINIT_USIZE) {
    ERROR("The enclave %p has not been initialized, call mmap first!", handle);
    goto failure;
  }
  *phys_offset = encl->phys_start;
  return SUCCESS;
failure:
  return FAILURE;
}

int mprotect_enclave(
    enclave_handle_t handle,
    usize vstart,
    usize size,
    memory_access_right_t flags,
    enclave_segment_type_t tpe)
{
  enclave_t* encl = NULL;
  enclave_segment_t* segment = NULL; 
  encl = find_enclave(handle);
  if (encl == NULL) {
    ERROR("Unable to find the enclave.");
    goto failure;
  } 
  if (encl->pid != current->pid) {
    ERROR("Wrong pid for enclave");
    ERROR("Expected: %d, got: %d", encl->pid, current->pid);
    goto failure;
  }
  if (encl->virt_start == UNINIT_USIZE) {
    ERROR("The enclave %p doesn't have mmaped memory.", handle);
    goto failure;
  }
  // Check the mprotect has the correct bounds.
  if (dll_is_empty(&(encl->segments)) && vstart != encl->virt_start) {
    ERROR("Out of order specification of segment: wrong start");
    ERROR("Expected: %llx, got: %llx", encl->virt_start, vstart);
    goto failure;
  }
  if (!dll_is_empty(&(encl->segments)) 
      && (encl->segments.tail->vstart + encl->segments.tail->size) != vstart) {
    ERROR("Out of order specification of segment: non-contiguous.");
    ERROR("Expected %llx, got: %llx",
        (encl->segments.tail->vstart + encl->segments.tail->size), vstart);
    goto failure;
  }
  if(vstart + size > encl->virt_start + encl->size) {
    ERROR("Mapping overflows the registered memory region.");
    ERROR("Max valid address: %llx, got: %llx", encl->virt_start + encl->size,
        vstart + size);
    goto failure;
  }
  
  // Add the segment.
  segment = kmalloc(sizeof(enclave_segment_t), GFP_KERNEL);
  if (segment == NULL) {
    ERROR("Unable to allocate new segment");
  }
  memset(segment, 0, sizeof(enclave_segment_t));
  segment->vstart = vstart;
  segment->size = size;
  segment->flags = flags;
  segment->tpe = tpe;
  dll_init_elem(segment, list);
  dll_add(&(encl->segments), segment, list);
  DEBUG("Mprotect success for enclave %lld, start: %llx, end: %llx", 
      handle, vstart, vstart + size);
  return SUCCESS;
failure:
  return FAILURE;
}

int set_traps(enclave_handle_t handle, usize traps)
{
  enclave_t* encl = find_enclave(handle);
  if (encl == NULL) {
    ERROR("Unable to find the enclave");
    goto failure;
  }
  encl->traps = traps;
  return SUCCESS;
failure: 
  return FAILURE;
}

int set_cores(enclave_handle_t handle, usize core_map)
{
  enclave_t* encl = find_enclave(handle);
  if (encl == NULL) {
    ERROR("Unable to find the enclave");
    goto failure;
  }
  encl->cores = core_map;

  // Allocate the array.
  // TODO we could be less generous with the allocation.
  encl->entries.size = 64;
  encl->entries.entries = kcalloc(sizeof(enclave_entry_t), 64, GFP_KERNEL);
  if (encl->entries.entries == NULL) {
    ERROR("Unable to allocate the enclave entry array.");
    goto failure;
  }
  return SUCCESS;
failure: 
  return FAILURE;
}

int set_perm(enclave_handle_t handle, usize perm)
{
  enclave_t* encl = find_enclave(handle);
  if (encl == NULL) {
    ERROR("Unable to find the enclave");
    goto failure;
  }
  encl->perm = perm;
  return SUCCESS;
failure: 
  return FAILURE;
}

int set_switch(enclave_handle_t handle, usize sw)
{
  enclave_t* encl = find_enclave(handle);
  if (encl == NULL) {
    ERROR("Unable to find the enclave");
    goto failure;
  }
  encl->switch_type = sw;
  return SUCCESS;
failure: 
  return FAILURE;
}

int set_entry_on_core(
    enclave_handle_t handle,
    usize core,
    usize cr3,
    usize rip,
    usize rsp)
{
  enclave_t* encl = find_enclave(handle);
  if (encl == NULL) {
    ERROR("Unable to find the enclave");
    goto failure;
  }
  if ((encl->cores & (1 << core)) == 0) {
    ERROR("Trying to set entry point on unallowed core");
    goto failure;
  }

  if (core >= encl->entries.size) {
    ERROR("The supplied core is greater than the number of supported cores");
  }

  encl->entries.entries[core].cr3 = cr3;
  encl->entries.entries[core].rip = rip;
  encl->entries.entries[core].rsp = rsp;
  return SUCCESS;
failure:
  return FAILURE;
}

int commit_enclave(enclave_handle_t handle)
{
  usize vbase = 0;
  usize poffset = 0;
  enclave_t* encl = NULL;
  enclave_segment_t* segment = NULL;
  encl = find_enclave(handle);
  if (encl == NULL) {
    ERROR("Unable to find the enclave.");
    goto failure;
  } 
  if (encl->pid != current->pid) {
    ERROR("Wrong pid for enclave");
    ERROR("Expected: %d, got: %d", encl->pid, current->pid);
    goto failure;
  }
  if (encl->virt_start == UNINIT_USIZE) {
    ERROR("The enclave %p doesn't have mmaped memory.", handle);
    goto failure;
  }
  if (dll_is_empty(&encl->segments)) {
    ERROR("Missing segments for enclave %p", handle);
    goto failure;
  }
  if ((encl->segments.tail->vstart + encl->segments.tail->size)
      != (encl->virt_start + encl->size)) {
    ERROR("Some segments were not specified for the enclave %p", handle);
    goto failure;
  }
  if (encl->domain_id != UNINIT_DOM_ID) {
    ERROR("The enclave %p is already committed.", handle);
    goto failure;
  }

  if (encl->entries.entries == NULL) {
    ERROR("The entries should have been initialized.");
    goto failure;
  }

  // All checks are done, call into the capability library.
  if (create_domain(&(encl->domain_id)) != SUCCESS) {
    ERROR("Monitor rejected the creation of a domain for enclave %p", handle);
    goto failure;
  }

  // Add the segments.
  vbase = encl->virt_start;
  poffset = encl->phys_start;
  dll_foreach(&(encl->segments), segment, list) {
    usize paddr = segment->vstart - vbase + poffset; 
    switch(segment->tpe) {
      case SHARED:
        if (share_region(
              encl->domain_id, 
              paddr,
              paddr + segment->size,
              segment->flags) != SUCCESS) {
          ERROR("Unable to share segment %llx -- %llx {%x}", segment->vstart,
              segment->size, segment->flags);
          goto delete_fail;
        }
        break;
      case CONFIDENTIAL:
        if (grant_region(
              encl->domain_id,
              paddr,
              paddr + segment->size,
              segment->flags) != SUCCESS) {
          ERROR("Unable to share segment %llx -- %llx {%x}", segment->vstart,
              segment->size, segment->flags);
          goto delete_fail;
        }
        break;
      default:
        ERROR("Invalid tpe for segment!");
        goto delete_fail;
    }
    DEBUG("Registered segment with tyche: %llx -- %llx [%x]",
        paddr, paddr + segment->size, segment->tpe);
  }

  // Set the cores and traps.
  if (set_domain_traps(encl->domain_id, encl->traps) != SUCCESS) {
    ERROR("Unable to set the traps for the enclave.");
    goto delete_fail;
  }
  if (set_domain_cores(encl->domain_id, encl->cores) != SUCCESS) {
    ERROR("Unable to set the cores for the enclave");
    goto delete_fail;
  }

  if (set_domain_perm(encl->domain_id, encl->perm) != SUCCESS) {
    ERROR("Unable to set the permissions for the enclave.");
    goto delete_fail;
  }

  if (set_domain_switch(encl->domain_id, encl->switch_type) != SUCCESS) {
    ERROR("Unable to set the enclave's switch type.");
    goto delete_fail;
  }

  // Set the entries for all the cores of the enclave.
  do {
    usize value = encl->cores, counter = 0;
    while (value > 0) {
      if ((value & 1) != 0) {
        if (set_domain_entry_on_core(
          encl->domain_id,
          counter,
          encl->entries.entries[counter].cr3,
          encl->entries.entries[counter].rip,
          encl->entries.entries[counter].rsp) != SUCCESS) {
          ERROR("Unable to set the entry point on core %lld, for %llx", counter, encl->cores);
          goto delete_fail;
        } 
      }
      counter++;
      value >>= 1;
    }
  } while(0);

  // Commit the enclave.
  if (seal_domain(encl->domain_id) != SUCCESS) {
    ERROR("Unable to seal enclave %p", handle);
    goto delete_fail;
  }
  
  DEBUG("Managed to seal domain %lld | encl %p", encl->domain_id, encl->handle);
  // We are all done!
  return SUCCESS;
delete_fail:
  if (revoke_domain(encl->domain_id) != SUCCESS) {
    ERROR("Failed to revoke the domain %lld for enclave %p.",
        encl->domain_id, handle);
  }
  encl->domain_id = UNINIT_DOM_ID;
failure:
  return FAILURE;
}

int switch_enclave(enclave_handle_t handle, void* args)
{
  enclave_t* enclave = NULL;
  enclave = find_enclave(handle);
  if (enclave == NULL) {
    ERROR("Unable to find the enclave %p", handle);
    goto failure;
  }
  DEBUG("About to try to switch to domain %lld| encl %lld",
      enclave->domain_id, enclave->handle);
  if (switch_domain(enclave->domain_id, args) != SUCCESS) {
    ERROR("Unable to switch to enclave %p", enclave->handle);
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int delete_enclave(enclave_handle_t handle)
{
  enclave_t* encl = NULL;
  enclave_segment_t* segment = NULL;
  encl = find_enclave(handle);
  if (encl == NULL) {
    ERROR("The enclave %p does not exist.", handle);
    goto failure;
  }
  if (encl->domain_id == UNINIT_DOM_ID) {
    goto delete_encl_struct;
  }
  if (revoke_domain(encl->domain_id) != SUCCESS) {
    ERROR("Unable to delete the domain %lld for enclave %p",
        encl->domain_id, handle);
    goto failure;
  }

delete_encl_struct:
  // Delete all segments;
  while(!dll_is_empty(&(encl->segments))) {
    segment = encl->segments.head;
    dll_remove(&(encl->segments), segment, list);
    kfree(segment);
    segment = NULL;
  }

  // Delete the enclave memory region.
  free_pages_exact(phys_to_virt((phys_addr_t)(encl->phys_start)), encl->size);
  dll_remove(&enclaves, encl, list);
  kfree(encl->entries.entries);
  kfree(encl);
  return SUCCESS;
failure:
  return FAILURE;
}

int debug_addr(usize virt_addr, usize* phys_addr)
{
  if (phys_addr == NULL) {
    ERROR("Provided phys_addr is null.");
    goto failure;
  }
  //*phys_addr = (usize) virt_to_phys((void*)virt_addr);
  if (walk_and_collect_region(virt_addr, 0x1000, phys_addr) != SUCCESS) {
    ERROR("Walk and collect failed!");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}
