#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>
#include <asm/io.h>
#include "enclave.h"
#include "mapper.h"


static addr_t va_to_pa(addr_t addr, pt_profile_t* prof) {
  return (addr_t) virt_to_phys((void*) addr);
}

static addr_t pa_to_va(addr_t addr, pt_profile_t* prof) {
  return (addr_t) phys_to_virt((phys_addr_t) addr);
}

static entry_t* allocate(void* ptr)
{
  map_info_t* info = NULL;
  void* allocation = NULL;
  struct pa_region_t* region = NULL;
  struct pa_region_t* in_all_pages = NULL;
  entry_t* page = NULL;

  info = (map_info_t*) ptr;
  if (info == NULL || info->profile == NULL || info->enclave == NULL) {
    return NULL;
  }
  
  allocation = alloc_pages_exact(PT_PAGE_SIZE, GFP_KERNEL);
  if (allocation == NULL || ((uint64_t)allocation) % PT_PAGE_SIZE != 0) {
    return NULL;
  }
  memset(allocation, 0, PT_PAGE_SIZE);
  // Get the physical address.
  page = (entry_t*) virt_to_phys(allocation); 

  // Create a pa entry in the enclave.
  region = kmalloc(sizeof(struct pa_region_t), GFP_KERNEL);
  if (region == NULL) {
    goto failure_unmap;
  }
  // Populate the region's attributes.
  region->start = (uint64_t)(page);
  region->end = region->start + PT_PAGE_SIZE;
  region->tpe = CONFIDENTIAL;
  region->flags = TE_READ | TE_WRITE | TE_SUPER;
  dll_init_elem(region, list);
  dll_init_elem(region, globals);
  
  // Add the region to the enclave's page table.
  dll_add(&(info->enclave->pts), region, list);

  // Add a copy of the region in the enclave all regions.
  in_all_pages = kmalloc(sizeof(struct pa_region_t), GFP_KERNEL);
  if (in_all_pages == NULL) {
    goto failure_remove;
  }
  in_all_pages->start = region->start;
  in_all_pages->end = region->end;
  in_all_pages->tpe = region->tpe;
  in_all_pages->flags = region->flags; 
  dll_init_elem(in_all_pages, list);
  dll_init_elem(in_all_pages, globals);
  
  // After that call, it is unsafe to access in_all_pages.
  if (add_merge_global(info->enclave, in_all_pages) != 0) {
    pr_err("[TE]: Failure to add a page in enclave_pts from allocate.\n");
    goto failure_remove;
  }

  // return the value
  return page;
failure_remove:
  dll_remove(&(info->enclave->pts), region, list);
failure_unmap:
  free_pages_exact(allocation, PT_PAGE_SIZE);
  return NULL;
}

static entry_t translate_flags(uint64_t flags)
{
  entry_t translation = 0;
  if (flags != 0) {
    translation |= PT_PP;
  }
  if ((flags & TE_EXEC) == 0) {
    translation |= PT_NX;
  }
  if ((flags & TE_WRITE) == TE_WRITE) {
    translation |= PT_RW;
  }
  if ((flags & TE_SUPER) == 0) {
    translation |= PT_USR;
  }
  return translation;
}

callback_action_t default_mapper(entry_t* entry, level_t lvl, struct pt_profile_t* profile)
{
  map_info_t* info = NULL;
  entry_t* new_page = NULL;
  int is_huge = 0;
  entry_t size = 0;
  // There is something going wrong.
  if (entry == NULL || profile == NULL || profile->extras == NULL) {
    pr_err("default mapper received a null value.");
    return ERROR;
  }
  info = (map_info_t*)(profile->extras);
  if (info->pa_region == NULL) {
    return ERROR;
  }
  size = info->pa_region->end - info->pa_region->start;
  //TODO implement.
  switch(lvl) {
    case PT_PGD:
      // We have a huge mapping.
      if (size == PT_PGD_PAGE_SIZE) {
        is_huge = 1;
        goto entry_page; 
      }
      // Normal mapping.
      goto normal_page;
      break;
    case PT_PMD:
      if (size == PT_PMD_PAGE_SIZE) {
        is_huge = 1; 
        goto entry_page;
      }
      goto normal_page;
      break;
    case PT_PML4:
      // Easy case, just map the entry.
      goto normal_page;
    case PT_PTE:
      if (size != PT_PAGE_SIZE) {
        // There is a mismatch.
        return ERROR;
      }
      is_huge = 0;
      goto entry_page;
      break;
  }

// Mapping a page.
entry_page:
  *entry = (info->pa_region->start & PT_PHYS_PAGE_MASK)
    | translate_flags(info->region->flags) | 0x60;
  if (is_huge) {
    *entry |= PT_PAGE_PSE;
  }
  // Move to the next region.
  info->pa_region = info->pa_region->list.next;
  return WALK;
// Allocating a new entry
normal_page:
  new_page = profile->allocate(profile->extras);
  *entry = (((entry_t)new_page)) | info->intermed_flags;
  return WALK;
}

static int map_region(struct region_t* region, pt_profile_t* profile) {
  map_info_t* info = NULL;
  if (region == NULL || profile == NULL || profile->extras == NULL) {
    return -1;
  }
  info = (map_info_t*)(profile->extras);
  info->region = region;
  // We walk the physical page exactly in the same order we collected them.
  info->pa_region = region->pas.head;
  // Default flags for intermediary level mappings.
  info->intermed_flags = PT_PP | PT_RW | PT_ACC | PT_USR | PT_DIRT;//| PT_NX;
  return pt_walk_page_range(info->enclave->cr3, PT_PML4, region->start, region->end, profile);
}

/// Create the tree for the enclave.
int build_enclave_cr3(struct enclave_t* encl) {
  struct region_t* reg = NULL;
  pt_profile_t profile = x86_64_profile;
  map_info_t info = {
    .intermed_flags = 0,
    .region = NULL,
    .pa_region = NULL,
    .profile = &profile, 
    .enclave = encl,
  };
  profile.allocate = allocate;
  profile.pa_to_va = pa_to_va;
  profile.va_to_pa = va_to_pa;
  profile.extras = (void*) &info;
  profile.how = x86_64_how_map; 

  // Allocate the root.
  encl->cr3 = (uint64_t) allocate(&info);

  // The mappers.
  profile.mappers[PT_PTE] = default_mapper;
  profile.mappers[PT_PMD] = default_mapper;
  profile.mappers[PT_PGD] = default_mapper;
  profile.mappers[PT_PML4] = default_mapper;

  // Go through each region.
  dll_foreach(&(encl->regions), reg, list) {
    struct pa_region_t* curr = NULL;
    struct pa_region_t* copy = NULL;
    if (map_region(reg, &profile) != 0) {
      // There was a failure.
      return -1;
    }
    // Merge all the physical regions in all_pages.
    dll_foreach(&(reg->pas), curr, list) {
      // TODO error handling is quite hard here, we should undo stuff...
      copy = kmalloc(sizeof(struct pa_region_t), GFP_KERNEL); 
      if (!copy) {
        pr_err("[TE]: Failed to kmalloc a pa_region_t.\n");
        return -1;
      }
      copy->start = curr->start;
      copy->end = curr->end;
      copy->tpe = curr->tpe;
      copy->flags = curr->flags;
      dll_init_elem(copy, list);
      dll_init_elem(copy, globals);
      if (add_merge_global(encl, copy) !=0 ) {
        pr_err("[TE]: unable to add and merge the region's pas.\n");
        return -1;
      } 
    }
  }
  return 0;
}
