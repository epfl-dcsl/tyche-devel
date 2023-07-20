#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "dll.h"
#include "elf64.h"
#include "driver_ioctl.h"
#include "pts.h"
#include "tyche_enclave.h"
#include "x86_64_pt.h"
#include "common.h"
#include "enclave_loader.h"
#include "enclave_rt.h"
#include "tychools.h"

// ———————————————— Helper functions from include/tychools.h ———————————————— //

int is_confidential(tyche_phdr_t tpe)
{
  switch (tpe) {
    case USER_STACK_CONF:
    case KERNEL_STACK_CONF:
    case PAGE_TABLES_CONF:
    case USER_CONFIDENTIAL:
    case KERNEL_CONFIDENTIAL:
      return 1;
      break;
    default: 
      return 0;
      break;
  }
  return 0;
}

int is_loadable(tyche_phdr_t tpe)
{
    if (tpe < USER_STACK_SB || tpe > KERNEL_CONFIDENTIAL) {
      return 0;
    }
    return 1;
}

// ————————————— Loader functions from include/enclave_loader.h ————————————— //

int tychools_init_enclave_with_cores_traps(
    enclave_t* enclave,
    const char* file,
    usize cores,
    usize traps)
{
  if (enclave == NULL || file == NULL) {
    ERROR("Null argument provided: encl(%s), file(%s)", enclave, file);
    goto failure;
  }
  memset(enclave, 0, sizeof(enclave_t));
  enclave->traps = traps;
  enclave->core_map = cores;
  enclave->config.loader_type = TYCHOOL_LOADER;
  LOG("parsing enclave %s", file);
  if (tychools_parse_enclave(enclave, file) != SUCCESS) {
    ERROR("Unable to parse the enclave %s.", file);
    goto failure;
  }
  LOG("loading enclave %s", file);
  if (tychools_load_enclave(enclave) != SUCCESS) {
    ERROR("Unable to load the enclave %s", file);
    goto failure;
  }
  // All done!
  return SUCCESS;
failure:
  return FAILURE;
}

int tychools_parse_enclave(enclave_t* enclave, const char* file)
{
  size_t segments_size = 0;

  // Common checks.
  if (file == NULL) {
    ERROR("Supplied file is null.");
  }
  if (enclave == NULL) {
    ERROR("Enclave structure is null."); 
    goto failure;
  }
  dll_init_list(&(enclave->config.shared_sections));
  
  // Open the enclave file.
  enclave->parser.fd = open(file, O_RDONLY);
  if (enclave->parser.fd < 0) {
    ERROR("Could not open '%s': %d", file, errno);
    goto failure;
  }

  // Parse the ELF.
  read_elf64_header(enclave->parser.fd, &(enclave->parser.header));
  read_elf64_segments(enclave->parser.fd,
      enclave->parser.header, &(enclave->parser.segments)); 
  //@note: We do not need to parse the sections as tychools works on segments. 

  // Set up the entry point.
  enclave->config.entry = enclave->parser.header.e_entry;

  // Find the stack and the shared regions.
  for (int i = 0; i < enclave->parser.header.e_phnum; i++) {
    Elf64_Phdr* segment = &enclave->parser.segments[i];
    // Found the user stack.
    if (segment->p_type == USER_STACK_SB || segment->p_type == USER_STACK_CONF) {
      enclave->config.user_stack = segment->p_vaddr + segment->p_memsz - STACK_OFFSET_TOP; 
    }
    // Found the kernel stack.
    if (segment->p_type == KERNEL_STACK_SB || segment->p_type == KERNEL_STACK_CONF) {
      enclave->config.stack = segment->p_vaddr + segment->p_memsz - STACK_OFFSET_TOP;
    }
    // Found a shared segment.
    if (segment->p_type == KERNEL_SHARED || segment->p_type == USER_SHARED) {
      enclave_shared_memory_t *shared = malloc(sizeof(enclave_shared_memory_t));
      if (shared == NULL) {
        ERROR("Unable to malloc enclave_shared_memory_t");
        goto failure;
      } 
      memset(shared, 0, sizeof(enclave_shared_memory_t));
      shared->tpe = TYCHE_SHARED_SEGMENT;
      shared->shared.segment = segment;
      dll_init_elem(shared, list);
      dll_add(&(enclave->config.shared_sections), shared, list);
    }
    // Found the page tables.
    if (segment->p_type == PAGE_TABLES_SB || segment->p_type == PAGE_TABLES_CONF) {
      enclave->config.cr3 = segment->p_vaddr;
      //TODO figure out if we want to keep a pointer to the segment.
    }
  }
  
  // Compute the entire size of all segments.
  for (int i = 0; i < enclave->parser.header.e_phnum; i++) {
    Elf64_Word tpe = enclave->parser.segments[i].p_type;
    // Only consider loadable segments instrumented by tychools.
    if (!is_loadable(tpe)) {
      continue;
    }
    segments_size += align_up(enclave->parser.segments[i].p_memsz);
  }
  if (segments_size % PAGE_SIZE != 0) {
    ERROR("The computed size for the segments is %zu", segments_size);
    goto close_failure;
  }
  DEBUG("The overall size for the binary is %zx", segments_size);
  enclave->map.size = segments_size;
  
  // We are done for now, next step is to load the enclave.
  LOG("Parsed tychools binary %s", file);
  return SUCCESS;
close_failure:
  close(enclave->parser.fd);
failure:
  return FAILURE;
}

int tychools_load_enclave(enclave_t* enclave)
{
  usize size = 0;
  usize phys_size = 0;
  if (enclave == NULL) {
    ERROR("The enclave is null.");
    goto failure;
  }

  if (enclave->parser.segments == NULL) {
    ERROR("The enclave is not parsed. Call parse_enclave first!");
    goto failure;
  }

  // Open the driver.
  enclave->handle = open(ENCLAVE_DRIVER, O_RDWR);
  if (enclave->handle < 0) {
    ERROR("Unable to create an enclave with open %s", ENCLAVE_DRIVER);
    goto failure;
  }

  // Mmap the size of memory we need.
  if (ioctl_mmap(
        enclave->handle,
        enclave->map.size,
        &(enclave->map.virtoffset)) != SUCCESS) {
    goto failure;
  }
  
  // Get the physoffset.
  if (ioctl_getphysoffset_enclave(
        enclave->handle,
        &(enclave->map.physoffset)) != SUCCESS) {
    goto failure;
  }

  // Add the offset to the enclave's cr3.
  enclave->config.cr3 += enclave->map.physoffset;
  DEBUG("The enclave's cr3 is at %llx", enclave->config.cr3);

  // Copy the enclave's content.
  phys_size = 0;
  for (int i = 0; i < enclave->parser.header.e_phnum; i++) {
    Elf64_Phdr seg = enclave->parser.segments[i];
    // The segment is not loadable.
    if (!is_loadable(seg.p_type)) {
      continue;
    }
    addr_t dest = enclave->map.virtoffset + phys_size;
    addr_t size = align_up(seg.p_memsz);
    memory_access_right_t flags = translate_flags_to_tyche(seg.p_flags);
    load_elf64_segment(enclave->parser.fd, (void*) dest, seg);

    // If segment is shared, fix it in the shared_segments.
    // For now, do it in a non-efficient way.
    enclave_shared_memory_t* shared =  NULL;
    dll_foreach(&(enclave->config.shared_sections), shared, list) {
      if (shared->tpe == TYCHE_SHARED_SEGMENT && shared->shared.segment->p_vaddr == seg.p_vaddr) {
          shared->untrusted_vaddr = dest;
      }
    }

    // Fix the page tables here.
    if (seg.p_type == PAGE_TABLES_CONF || seg.p_type == PAGE_TABLES_SB) {
      uint64_t* start = (uint64_t*) dest;
      uint64_t* end = (uint64_t*)(((uint64_t) dest) + size);
      for (; start < end; start++) {
        if (*start != 0) {
          *start += enclave->map.physoffset;
        }
      } 
    }

    // Now map the segment.
    int conf_or_shared = is_confidential(seg.p_type)? CONFIDENTIAL : SHARED; 
    if (ioctl_mprotect_enclave(
          enclave->handle,
          dest,
          size,
          flags,
          conf_or_shared) != SUCCESS) {
      ERROR("Unable to map segment for enclave %lld at %llx",
          enclave->handle, dest);
      goto failure;
    }
    // Update the current size.
    phys_size+= size;
  } 
  DEBUG("Done mprotecting enclave %lld's sections", enclave->handle);

  // Set the cores and traps.
  if (ioctl_set_traps(enclave->handle, enclave->traps) != SUCCESS) {
    ERROR("Unable to set the traps for the enclave %lld", enclave->handle);
    goto failure;
  }
 
  if (ioctl_set_cores(enclave->handle, enclave->core_map) != SUCCESS) {
    ERROR("Unable to set the cores for the enclave %lld", enclave->handle);
    goto failure;
  }

  // TODO(aghosn) expose this through the SDK.
  // I don't do it now because I'll need some time to refactor libraries to avoid
  // having so many layers of forwarding. It's becoming really annoying.
  if (ioctl_set_perms(enclave->handle, DEFAULT_PERM) != SUCCESS) {
    ERROR("Unable to set the permission on enclave %lld", enclave->handle);
    goto failure;
  }

  // TODO(aghosn) same as above.
  if (ioctl_set_switch(enclave->handle, SharedVCPU) != SUCCESS) {
      ERROR("Unable to set the switch type.");
      goto failure;
  } 

  // TODO(aghosn) same as above as well.
  if (ioctl_set_entry_on_core(
        enclave->handle,
        0,
        enclave->config.cr3,
        enclave->config.entry,
        enclave->config.stack) != SUCCESS) {
      ERROR("Unable to set the entry on core 0");
      goto failure;
  }

  // Commit the enclave.
  if (ioctl_commit_enclave(enclave->handle)!= SUCCESS) {
    ERROR("Unable to commit the enclave %lld", enclave->handle);
    goto failure;
  } 
  DEBUG("Done loading enclave %lld", enclave->handle);
  return SUCCESS;
failure:
  return FAILURE;
}


