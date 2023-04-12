#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/mm_types.h>
#include <asm/io.h>

#define TYCHE_DEBUG 1
#include "common.h"
#include "enclaves.h"
#include "tyche_capabilities.h"

// ———————————————————————————————— Globals ————————————————————————————————— //

static dll_list(enclave_t, enclaves);
static dll_list(mmap_segment_t, mapped_segments);

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
    ERROR("Attempt to access enclave %lld from wrong pid", handle);
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
  dll_init_list((&mapped_segments));
  init_capabilities();
}


int create_enclave(enclave_handle_t handle, usize spawn, usize comm)
{
  enclave_t* encl = NULL;
  encl = find_enclave(handle);
  if (encl != NULL) {
    ERROR("The enclave with handle %lld already exists.", handle);
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
  dll_init_list(&(encl->segments));
  dll_init_elem(encl, list);

  // Add the enclave to the list.
  dll_add((&enclaves), encl, list);
  LOG("A new enclave was added to the driver with id %lld", handle);
  return SUCCESS;
failure:
  return FAILURE;
}

int mmap_segment(struct vm_area_struct *vma)
{
  void* allocation = NULL;
  usize size = 0;
  mmap_segment_t* segment = NULL;
  unsigned long pfn = 0;
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

  // Create the segment.
  segment = kmalloc(sizeof(mmap_segment_t), GFP_KERNEL);
  if (segment == NULL) {
    ERROR("Unable to allocate mmap segment.");
    goto failure;
  }
  segment->pid = current->pid;

  // Allocate a contiguous memory region.
  size = vma->vm_end - vma->vm_start;
  allocation = alloc_pages_exact(size, GFP_KERNEL); 
  if (allocation == NULL) {
    ERROR("Alloca pages exact failed to allocate the pages.");
    goto fail_free;
  }
  memset(allocation, 0, size);
  // Prevent pages from being collected.
  for (int i = 0; i < (size/PAGE_SIZE); i++) {
    char* mem = ((char*)allocation) + PAGE_SIZE;
    SetPageReserved(virt_to_page((unsigned long)mem));
  }

  // Map the result into the user address space.
  pfn = page_to_pfn(virt_to_page(allocation)); 
  if (remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot)) {
    ERROR("Unable to map the allocated physical memory into the user process.");
    goto fail_free_pages;
  }

  // Set the values inside the enclave structure.
  segment->phys_start = (usize) virt_to_phys(allocation);
  segment->virt_start = (usize) vma->vm_start;
  segment->size = size;
  dll_init_elem(segment, list);
  dll_add(&mapped_segments, segment, list);
  DEBUG("mmap success pa: %llx va: %llx, size: %llx",
      segment->phys_start, segment->virt_start, segment->size);
  return SUCCESS;
fail_free_pages:
  free_pages_exact(allocation, size);
fail_free:
  kfree(segment);
failure:
  return FAILURE;
}

int get_physoffset_enclave(
    enclave_handle_t handle,
    usize virtaddr,
    usize* phys_offset)
{
  enclave_t* encl = NULL;
  mmap_segment_t* segment = NULL;
  if (phys_offset == NULL) {
    ERROR("The provided phys_offset variable is null.");
    goto failure;
  }
  encl = find_enclave(handle);
  if (encl == NULL) {
    ERROR("The handle %lld does not correspond to an enclave.", handle);
    goto failure;
  }
  if (encl->pid != current->pid) {
    ERROR("Wrong pid for enclave");
    ERROR("Expected: %d, got: %d", encl->pid, current->pid);
    goto failure;
  }
  if (encl->virt_start != UNINIT_USIZE || encl->phys_start != UNINIT_USIZE) {
    ERROR("The enclave %lld has already been initialized.", handle);
    goto failure;
  }
  dll_foreach(&mapped_segments, segment, list) {
    if (segment->virt_start == virtaddr && segment->pid == encl->pid) {
      // Found the right segment.
      break;
    }  
  } 
  if (segment == NULL) {
    ERROR("Unable to find segment for %lld at %llx", handle, virtaddr);
    goto failure;
  }
  dll_remove(&mapped_segments, segment, list);
  encl->virt_start = segment->virt_start;
  encl->phys_start = segment->phys_start;
  encl->size = segment->size;

  // Free the segment now.
  kfree(segment);
  segment = NULL;
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
    ERROR("The enclave %lld doesn't have mmaped memory.", handle);
    goto failure;
  }
  // Check the mprotect has the correct bounds.
  if (dll_is_empty(&(encl->segments)) && vstart != encl->virt_start) {
    ERROR("Out of order specification of segment");
    ERROR("Expected: %llx, got: %llx", encl->virt_start, vstart);
    goto failure;
  }
  if (!dll_is_empty(&(encl->segments)) 
      && (encl->segments.tail->vstart + encl->segments.tail->size) != vstart) {
    ERROR("Out of order specification of segment.");
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

int commit_enclave(enclave_handle_t handle, usize cr3, usize rip, usize rsp)
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
    ERROR("The enclave %lld doesn't have mmaped memory.", handle);
    goto failure;
  }
  if (dll_is_empty(&encl->segments)) {
    ERROR("Missing segments for enclave %lld", handle);
    goto failure;
  }
  if ((encl->segments.tail->vstart + encl->segments.tail->size)
      != (encl->virt_start + encl->size)) {
    ERROR("Some segments were not specified for the enclave %lld", handle);
    goto failure;
  }
  if (encl->domain_id != UNINIT_DOM_ID) {
    ERROR("The enclave %lld is already committed.", handle);
    goto failure;
  }

  // All checks are done, call into the capability library.
  if (create_domain(&(encl->domain_id), 1, 1) != SUCCESS) {
    ERROR("Monitor rejected the creation of a domain for enclave %lld", handle);
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

  // Commit the enclave.
  if (seal_domain(encl->domain_id, ALL_CORES_MAP, cr3, rip, rsp) != SUCCESS) {
    ERROR("Unable to seal enclave %lld", handle);
    goto delete_fail;
  }
  
  DEBUG("Managed to seal domain %lld | encl %lld", encl->domain_id, encl->handle);
  // We are all done!
  return SUCCESS;
delete_fail:
  if (revoke_domain(encl->domain_id) != SUCCESS) {
    ERROR("Failed to revoke the domain %lld for enclave %lld.",
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
    ERROR("Unable to find the enclave %lld", handle);
    goto failure;
  }
  DEBUG("About to try to switch to domain %lld| encl %lld",
      enclave->domain_id, enclave->handle);
  if (switch_domain(enclave->domain_id, args) != SUCCESS) {
    ERROR("Unable to switch to enclave %lld", enclave->handle);
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
    ERROR("The enclave %lld does not exist.", handle);
    goto failure;
  }
  if (encl->domain_id == UNINIT_DOM_ID) {
    goto delete_encl_struct;
  }
  if (revoke_domain(encl->domain_id) != SUCCESS) {
    ERROR("Unable to delete the domain %lld for enclave %lld",
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
  kfree(encl);
  return SUCCESS;
failure:
  return FAILURE;
}
