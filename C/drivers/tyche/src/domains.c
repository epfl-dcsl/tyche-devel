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
#include "domains.h"
#include "tyche_capabilities.h"
#include "tyche_capabilities_types.h"

// ———————————————————————————————— Globals ————————————————————————————————— //

static dll_list(driver_domain_t, domains);

// ———————————————————————————— Helper Functions ———————————————————————————— //

static driver_domain_t* find_domain(domain_handle_t handle)
{
  driver_domain_t* dom = NULL;
  dll_foreach((&domains), dom, list) {
    if (dom->handle == handle) {
      break;
    }
  }
  if (dom == NULL) {
    goto failure;
  }
  if (dom->pid != current->pid) {
    ERROR("Attempt to access dom %p from wrong pid", handle);
    ERROR("Expected pid: %d, got: %d", dom->pid, current->pid);
    goto failure;
  }
  return dom;
failure:
  return NULL;
}


// ——————————————————————————————— Functions ———————————————————————————————— //

void driver_init_domains(void)
{
  dll_init_list((&domains));
  driver_init_capabilities();
}


int driver_create_domain(domain_handle_t handle)
{
  driver_domain_t* dom = NULL;
  dom = find_domain(handle);
  if (dom != NULL) {
    ERROR("The domain with handle %p already exists.", handle);
    goto failure;
  }
  dom = kmalloc(sizeof(driver_domain_t), GFP_KERNEL);
  if (dom == NULL) {
    ERROR("Failed to allocate a new driver_domain_t structure.");
    goto failure;
  }
  // Set up the structure.
  dom->pid = current->pid;
  dom->handle = handle;
  dom->domain_id = UNINIT_DOM_ID;
  dom->phys_start = UNINIT_USIZE;
  dom->virt_start = UNINIT_USIZE;
  dom->size = UNINIT_USIZE;
  // Init bitmaps. 
  dom->perm = 0;
  dom->cores = 0;
  dom->traps = 0;
  // Setup the entries.
  dom->entries.size = 0;
  dom->entries.entries = NULL;
  dll_init_list(&(dom->segments));
  dll_init_elem(dom, list);

  // Add the domain to the list.
  dll_add((&domains), dom, list);
  LOG("A new domain was added to the driver with id %p", handle);
  return SUCCESS;
failure:
  return FAILURE;
}

int driver_mmap_segment(domain_handle_t handle, struct vm_area_struct *vma)
{
  void* allocation = NULL;
  usize size = 0;
  driver_domain_t* dom = NULL;
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
  dom = find_domain(handle);
  if (dom == NULL) {
    ERROR("Unable to find the right domain.");
    goto failure;
  }
  if (dom->virt_start != UNINIT_USIZE || dom->phys_start != UNINIT_USIZE) {
    ERROR("The domain has already been initialized.");
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

  // Set the values inside the domain structure.
  dom->phys_start = (usize) virt_to_phys(allocation);
  dom->virt_start = (usize) vma->vm_start;
  dom->size = size;
  return SUCCESS;
fail_free_pages:
  free_pages_exact(allocation, size);
failure:
  return FAILURE;
}

int driver_get_physoffset_domain(domain_handle_t handle, usize* phys_offset)
{
  driver_domain_t* dom = NULL;
  if (phys_offset == NULL) {
    ERROR("The provided phys_offset variable is null.");
    goto failure;
  }
  dom = find_domain(handle);
  if (dom == NULL) {
    ERROR("The handle %p does not correspond to a domain.", handle);
    goto failure;
  }
  if (dom->virt_start == UNINIT_USIZE || dom->phys_start == UNINIT_USIZE) {
    ERROR("The domain %p has not been initialized, call mmap first!", handle);
    goto failure;
  }
  *phys_offset = dom->phys_start;
  return SUCCESS;
failure:
  return FAILURE;
}

int driver_mprotect_domain(
    domain_handle_t handle,
    usize vstart,
    usize size,
    memory_access_right_t flags,
    segment_type_t tpe)
{
  driver_domain_t* dom = NULL;
  segment_t* segment = NULL; 
  dom = find_domain(handle);
  if (dom == NULL) {
    ERROR("Unable to find the domain.");
    goto failure;
  } 
  if (dom->pid != current->pid) {
    ERROR("Wrong pid for domain");
    ERROR("Expected: %d, got: %d", dom->pid, current->pid);
    goto failure;
  }
  if (dom->virt_start == UNINIT_USIZE) {
    ERROR("The domain %p doesn't have mmaped memory.", handle);
    goto failure;
  }
  // Check the mprotect has the correct bounds.
  if (dll_is_empty(&(dom->segments)) && vstart != dom->virt_start) {
    ERROR("Out of order specification of segment: wrong start");
    ERROR("Expected: %llx, got: %llx", dom->virt_start, vstart);
    goto failure;
  }
  if (!dll_is_empty(&(dom->segments)) 
      && (dom->segments.tail->vstart + dom->segments.tail->size) != vstart) {
    ERROR("Out of order specification of segment: non-contiguous.");
    ERROR("Expected %llx, got: %llx",
        (dom->segments.tail->vstart + dom->segments.tail->size), vstart);
    goto failure;
  }
  if(vstart + size > dom->virt_start + dom->size) {
    ERROR("Mapping overflows the registered memory region.");
    ERROR("Max valid address: %llx, got: %llx", dom->virt_start + dom->size,
        vstart + size);
    goto failure;
  }
  
  // Add the segment.
  segment = kmalloc(sizeof(segment_t), GFP_KERNEL);
  if (segment == NULL) {
    ERROR("Unable to allocate new segment");
  }
  memset(segment, 0, sizeof(segment_t));
  segment->vstart = vstart;
  segment->size = size;
  segment->flags = flags;
  segment->tpe = tpe;
  dll_init_elem(segment, list);
  dll_add(&(dom->segments), segment, list);
  DEBUG("Mprotect success for domain %lld, start: %llx, end: %llx", 
      handle, vstart, vstart + size);
  return SUCCESS;
failure:
  return FAILURE;
}

int driver_set_traps(domain_handle_t handle, usize traps)
{
  driver_domain_t* dom = find_domain(handle);
  if (dom == NULL) {
    ERROR("Unable to find the domain");
    goto failure;
  }
  dom->traps = traps;
  return SUCCESS;
failure: 
  return FAILURE;
}

int driver_set_cores(domain_handle_t handle, usize core_map)
{
  driver_domain_t* dom = find_domain(handle);
  if (dom == NULL) {
    ERROR("Unable to find the domain");
    goto failure;
  }
  dom->cores = core_map;

  // Allocate the array.
  // TODO we could be less generous with the allocation.
  dom->entries.size = 64;
  dom->entries.entries = kcalloc(sizeof(entry_t), 64, GFP_KERNEL);
  if (dom->entries.entries == NULL) {
    ERROR("Unable to allocate the domain entry array.");
    goto failure;
  }
  return SUCCESS;
failure: 
  return FAILURE;
}

int driver_set_perm(domain_handle_t handle, usize perm)
{
  driver_domain_t* dom = find_domain(handle);
  if (dom == NULL) {
    ERROR("Unable to find the domain");
    goto failure;
  }
  dom->perm = perm;
  return SUCCESS;
failure: 
  return FAILURE;
}

int driver_set_switch(domain_handle_t handle, usize sw)
{
  driver_domain_t* dom = find_domain(handle);
  if (dom == NULL) {
    ERROR("Unable to find the domain");
    goto failure;
  }
  dom->switch_type = sw;
  return SUCCESS;
failure: 
  return FAILURE;
}

int driver_set_entry_on_core(
    domain_handle_t handle,
    usize core,
    usize cr3,
    usize rip,
    usize rsp)
{
  driver_domain_t* dom = find_domain(handle);
  if (dom == NULL) {
    ERROR("Unable to find the domain");
    goto failure;
  }
  if ((dom->cores & (1 << core)) == 0) {
    ERROR("Trying to set entry point on unallowed core");
    goto failure;
  }

  if (core >= dom->entries.size) {
    ERROR("The supplied core is greater than the number of supported cores");
  }

  dom->entries.entries[core].cr3 = cr3;
  dom->entries.entries[core].rip = rip;
  dom->entries.entries[core].rsp = rsp;
  return SUCCESS;
failure:
  return FAILURE;
}

int driver_commit_domain(domain_handle_t handle)
{
  usize vbase = 0;
  usize poffset = 0;
  driver_domain_t* dom = NULL;
  segment_t* segment = NULL;
  dom = find_domain(handle);
  if (dom == NULL) {
    ERROR("Unable to find the domain.");
    goto failure;
  } 
  if (dom->pid != current->pid) {
    ERROR("Wrong pid for dom");
    ERROR("Expected: %d, got: %d", dom->pid, current->pid);
    goto failure;
  }
  if (dom->virt_start == UNINIT_USIZE) {
    ERROR("The domain %p doesn't have mmaped memory.", handle);
    goto failure;
  }
  if (dll_is_empty(&dom->segments)) {
    ERROR("Missing segments for domain %p", handle);
    goto failure;
  }
  if ((dom->segments.tail->vstart + dom->segments.tail->size)
      != (dom->virt_start + dom->size)) {
    ERROR("Some segments were not specified for the domain %p", handle);
    goto failure;
  }
  if (dom->domain_id != UNINIT_DOM_ID) {
    ERROR("The domain %p is already committed.", handle);
    goto failure;
  }

  if (dom->entries.entries == NULL) {
    ERROR("The entries should have been initialized.");
    goto failure;
  }

  // All checks are done, call into the capability library.
  if (create_domain(&(dom->domain_id)) != SUCCESS) {
    ERROR("Monitor rejected the creation of a domain for domain %p", handle);
    goto failure;
  }

  // Add the segments.
  vbase = dom->virt_start;
  poffset = dom->phys_start;
  dll_foreach(&(dom->segments), segment, list) {
    usize paddr = segment->vstart - vbase + poffset; 
    switch(segment->tpe) {
      case SHARED:
        if (share_region(
              dom->domain_id, 
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
              dom->domain_id,
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
  if (set_domain_traps(dom->domain_id, dom->traps) != SUCCESS) {
    ERROR("Unable to set the traps for the domain.");
    goto delete_fail;
  }
  if (set_domain_cores(dom->domain_id, dom->cores) != SUCCESS) {
    ERROR("Unable to set the cores for the domain");
    goto delete_fail;
  }

  if (set_domain_perm(dom->domain_id, dom->perm) != SUCCESS) {
    ERROR("Unable to set the permissions for the domain.");
    goto delete_fail;
  }

  if (set_domain_switch(dom->domain_id, dom->switch_type) != SUCCESS) {
    ERROR("Unable to set the domain's switch type.");
    goto delete_fail;
  }

  // Set the entries for all the cores of the domain.
  do {
    usize value = dom->cores, counter = 0;
    while (value > 0) {
      if ((value & 1) != 0) {
        if (set_domain_entry_on_core(
          dom->domain_id,
          counter,
          dom->entries.entries[counter].cr3,
          dom->entries.entries[counter].rip,
          dom->entries.entries[counter].rsp) != SUCCESS) {
          ERROR("Unable to set the entry point on core %lld, for %llx",
              counter, dom->cores);
          goto delete_fail;
        } 
      }
      counter++;
      value >>= 1;
    }
  } while(0);

  // Commit the domain.
  if (seal_domain(dom->domain_id) != SUCCESS) {
    ERROR("Unable to seal domain %p", handle);
    goto delete_fail;
  }
  
  DEBUG("Managed to seal domain %lld | dom %p", dom->domain_id, dom->handle);
  // We are all done!
  return SUCCESS;
delete_fail:
  if (revoke_domain(dom->domain_id) != SUCCESS) {
    ERROR("Failed to revoke the domain %lld for domain %p.",
        dom->domain_id, handle);
  }
  dom->domain_id = UNINIT_DOM_ID;
failure:
  return FAILURE;
}

int driver_switch_domain(domain_handle_t handle, void* args)
{
  driver_domain_t* dom = NULL;
  dom = find_domain(handle);
  if (dom == NULL) {
    ERROR("Unable to find the domain %p", handle);
    goto failure;
  }
  DEBUG("About to try to switch to domain %lld| dom %lld",
      dom->domain_id, dom->handle);
  if (switch_domain(dom->domain_id, args) != SUCCESS) {
    ERROR("Unable to switch to domain %p", dom->handle);
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int driver_delete_domain(domain_handle_t handle)
{
  driver_domain_t* dom = NULL;
  segment_t* segment = NULL;
  dom = find_domain(handle);
  if (dom == NULL) {
    ERROR("The domain %p does not exist.", handle);
    goto failure;
  }
  if (dom->domain_id == UNINIT_DOM_ID) {
    goto delete_dom_struct;
  }
  if (revoke_domain(dom->domain_id) != SUCCESS) {
    ERROR("Unable to delete the domain %lld for domain %p",
        dom->domain_id, handle);
    goto failure;
  }

delete_dom_struct:
  // Delete all segments;
  while(!dll_is_empty(&(dom->segments))) {
    segment = dom->segments.head;
    dll_remove(&(dom->segments), segment, list);
    kfree(segment);
    segment = NULL;
  }

  // Delete the domain memory region.
  free_pages_exact(phys_to_virt((phys_addr_t)(dom->phys_start)), dom->size);
  dll_remove(&domains, dom, list);
  kfree(dom->entries.entries);
  kfree(dom);
  return SUCCESS;
failure:
  return FAILURE;
}
