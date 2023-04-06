#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/mm_types.h>
#include <asm/io.h>

#include "common.h"
#include "enclaves.h"
#include "tyche_capabilities.h"

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
    LOG("Enclave not found for handle %lld",  handle);
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

int mmap_enclave(enclave_handle_t handle, struct vm_area_struct *vma)
{
  void* allocation = NULL;
  usize size = 0;
  enclave_t* encl = NULL;
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

  // Checks on the enclave.
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
  if (encl->phys_start != UNINIT_USIZE || encl->virt_start != UNINIT_USIZE) {
    ERROR("The enclave %lld  already has memory @%llx", handle, encl->phys_start);
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
    char* mem = ((char*)allocation) + PAGE_SIZE;
    SetPageReserved(virt_to_page((unsigned long)mem));
  }

  // Map the result into the user address space.
  pfn = page_to_pfn(virt_to_page(allocation)); 
  if (remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot)) {
    ERROR("Unable to map the allocated physical memory into the user process.");
    goto fail_free;
  }

  // Set the values inside the enclave structure.
  encl->phys_start = (usize) virt_to_phys(allocation);
  encl->virt_start = (usize) vma->vm_start;
  encl->size = size;
  return SUCCESS;
fail_free:
  free_pages_exact(allocation, size);
failure:
  return FAILURE;
}

int get_physoffset_enclave(enclave_handle_t handle, usize* phys_offset)
{
  enclave_t* encl = NULL;
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
  if (encl->virt_start == UNINIT_USIZE) {
    ERROR("The enclave %lld is not initialized.", handle);
    ERROR("Call mmap first!");
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
    usize flags,
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
        if (share_region(encl->domain_id, paddr, paddr + segment->size,
              (memory_access_right_t) segment->flags) != SUCCESS) {
          ERROR("Unable to share segment %llx -- %llx {%llx}", segment->vstart,
              segment->size, segment->flags);
          goto delete_fail;
        }
        break;
      case CONFIDENTIAL:
        if (grant_region(encl->domain_id, paddr, paddr + segment->size,
              (memory_access_right_t) segment->flags) != SUCCESS) {
          ERROR("Unable to share segment %llx -- %llx {%llx}", segment->vstart,
              segment->size, segment->flags);
          goto delete_fail;
        }
        break;
      default:
        ERROR("Invalid tpe for segment!");
        goto delete_fail;
    }
  }

  // Commit the enclave.
  if (seal_domain(encl->domain_id, ALL_CORES_MAP, cr3, rip, rsp) != SUCCESS) {
    ERROR("Unable to seal enclave %lld", handle);
    goto delete_fail;
  }

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
