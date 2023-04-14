#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "elf64.h"
#include "driver_ioctl.h"
#include "pts.h"
#include "x86_64_pt.h"
#include "common.h"
#include "enclave_loader.h"
#include "enclave_rt.h"

// ——————————————————————————————— Constants ———————————————————————————————— //
const char* ENCLAVE_DRIVER = "/dev/tyche"; 
const char* SHARED_PREFIX = ".tyche_shared";

// ———————————————————————————— Local Functions ————————————————————————————— //
static memory_access_right_t translate_flags(Elf64_Word flags) {
  memory_access_right_t rights = 0;
  if ((flags & PF_R) == PF_R) {
    rights |= MEM_READ;
  }
  if ((flags & PF_X) == PF_X) {
    rights |= MEM_EXEC;
  }
  if ((flags & PF_W) == PF_W) {
    rights |= MEM_WRITE;
  }
  //TODO do user?
  rights |= MEM_SUPER;
  return rights;
}

static enclave_segment_type_t get_section_tpe_from_name(char* name)
{
  if (strncmp(SHARED_PREFIX, name, strlen(SHARED_PREFIX)) == 0) {
    return SHARED;
  }
  return CONFIDENTIAL;
}

// ——————————————————————————————— Functions ———————————————————————————————— //

int init_enclave(enclave_t* enclave, const char* file)
{
  if (parse_enclave(enclave, file) != SUCCESS) {
    ERROR("Failure to parse the enclave");
    goto failure;
  }
  if (load_enclave(enclave) != SUCCESS) {
    ERROR("Failure to load the enclave %s", file);
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int parse_enclave(enclave_t* enclave, const char* file)
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
  memset(enclave, 0, sizeof(enclave_t));
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
  read_elf64_sections(enclave->parser.fd,
      enclave->parser.header, &(enclave->parser.sections));
  enclave->parser.strings = read_section64(enclave->parser.fd,
      enclave->parser.sections[enclave->parser.header.e_shstrndx]);

  // Set up the entry point.
  enclave->config.entry = enclave->parser.header.e_entry;

  // Find the stack and the shared regions.
  for (int i = 0; i < enclave->parser.header.e_shnum; i++) {
    Elf64_Shdr section = enclave->parser.sections[i];
    // Look for shared sections.
    if (get_section_tpe_from_name(
          section.sh_name + enclave->parser.strings) == SHARED) {
      enclave_shared_section_t* shared = malloc(sizeof(enclave_shared_section_t));
      if (shared == NULL) {
        ERROR("Unable to malloc enclave_shared_section.");
        goto failure;
      }
      memset(shared, 0, sizeof(enclave_shared_section_t));
      shared->section = &(enclave->parser.sections[i]);
      dll_init_elem(shared, list);
      dll_add(&(enclave->config.shared_sections), shared, list);
      DEBUG("We found a shared region: %llx - %llx ",
          section.sh_addr, section.sh_addr + section.sh_size);
    } 

    // Check if this is the stack.
    if (strncmp(STACK_SECTION_NAME,
          section.sh_name + enclave->parser.strings,
          strlen(STACK_SECTION_NAME)) == 0) {
          enclave->config.stack = section.sh_addr + section.sh_size - STACK_OFFSET_TOP; 
          DEBUG("We found the enclave stack: %llx", enclave->config.stack);
        }
  }

  // Compute the entire size of all segments.
  for (int i = 0; i < enclave->parser.header.e_phnum; i++) {
    if (enclave->parser.segments[i].p_type != PT_LOAD) {
      continue;
    }
    segments_size += align_up(enclave->parser.segments[i].p_memsz);
  }
  if (segments_size % PAGE_SIZE != 0) {
    ERROR("The computed size for the segments is %zu", segments_size);
    goto close_failure;
  }
  DEBUG("The overall size for the binary is %zx", segments_size);
  
  // Create the page tables.
  if (create_page_tables(
        segments_size,
        &(enclave->parser.bump),
        &(enclave->parser.header),
        enclave->parser.segments) != SUCCESS) {
    ERROR("Unable to map the page tables.");
    goto close_failure;
  }

  // Put the temporary offset for the cr3.
  enclave->config.cr3 = enclave->parser.bump.phys_offset;
  DEBUG("The bump's phys_offset after creating the page tables: %llx",
      enclave->config.cr3);
  DEBUG("We consummed %d pages", enclave->parser.bump.idx);
  // We are done for now, next step is to load the enclave.
  return SUCCESS;
close_failure:
  close(enclave->parser.fd);
failure:
  return FAILURE;
}

int load_enclave(enclave_t* enclave)
{
  usize size = 0;
  usize phys_size = 0;
  if (enclave == NULL) {
    ERROR("The enclave is null.");
    goto failure;
  }

  if (enclave->parser.bump.pages == NULL || enclave->parser.segments == NULL) {
    ERROR("The enclave is not parsed. Call parse_enclave first!");
    goto failure;
  }

  // Open the driver.
  enclave->driver_fd = open(ENCLAVE_DRIVER, O_RDWR);
  if (enclave->driver_fd < 0) {
    ERROR("Unable to open the enclave driver %s", ENCLAVE_DRIVER);
    goto failure;
  }

  // Create an enclave.
  if (ioctl_create_enclave(enclave->driver_fd, &enclave->handle) != SUCCESS) {
    goto failure;
  }

  // Mmap the size of memory we need.
  enclave->map.size = enclave->parser.bump.phys_offset + enclave->parser.bump.idx * PAGE_SIZE; 
  if (ioctl_mmap(
        enclave->driver_fd,
        enclave->handle,
        enclave->map.size,
        &(enclave->map.virtoffset)) != SUCCESS) {
    goto failure;
  }

  // Get the physoffset.
  if (ioctl_getphysoffset_enclave(
        enclave->driver_fd,
        enclave->handle,
        enclave->map.virtoffset,
        &(enclave->map.physoffset)) != SUCCESS) {
    goto failure;
  }

  // Add the offset to the enclave's cr3.
  enclave->config.cr3 += enclave->map.physoffset;
  DEBUG("The enclave's cr3 is at %llx", enclave->config.cr3);

  // Fix the page tables.
  if (fix_page_tables(enclave->map.physoffset, &enclave->parser.bump) != SUCCESS) {
    ERROR("Unable to fix the page tables with the offset!");
    goto failure;
  }

  // Copy the enclave's content.
  phys_size = 0;
  for (int i = 0; i < enclave->parser.header.e_phnum; i++) {
    enclave_shared_section_t* shared_sect = NULL;
    Elf64_Phdr seg = enclave->parser.segments[i];
    if (seg.p_type != PT_LOAD) {
      continue;
    }
    addr_t dest = enclave->map.virtoffset + phys_size;
    addr_t size = align_up(seg.p_memsz);
    memory_access_right_t flags = translate_flags(seg.p_flags);
    load_elf64_segment(enclave->parser.fd, (void*) dest, seg);
    addr_t curr_va = seg.p_vaddr;
    usize local_size = 0;

    // Check if we have shared sections in this segment.
    dll_foreach(&(enclave->config.shared_sections), shared_sect, list) {
      Elf64_Shdr* section = shared_sect->section;
      usize virt_addr = dest + local_size; 
      if (section->sh_addr >= curr_va && section->sh_addr <= curr_va + size) {
        if (curr_va != section->sh_addr) {
          if (ioctl_mprotect_enclave(
              enclave->driver_fd,
              enclave->handle,
              /*curr_va*/ virt_addr,
              section->sh_addr - curr_va,
              flags,
              CONFIDENTIAL) != SUCCESS) {
            ERROR("Unable to map confidential segment for enclave %lld at %llx",
              enclave->handle, curr_va);
            goto failure;
          }
          local_size += section->sh_addr - curr_va;
          virt_addr += section->sh_addr - curr_va;
        }
        if (ioctl_mprotect_enclave(
              enclave->driver_fd,
              enclave->handle,
              virt_addr, 
              align_up(section->sh_size),
              flags,
              SHARED) != SUCCESS) {
          ERROR("Unable to map shared region for %lld at %llx",
              enclave->handle, section->sh_addr);
          goto failure;
        }
        // Update the virt_addr of the shared_sect;
        shared_sect->untrusted_vaddr = virt_addr;
        local_size += align_up(section->sh_size);
        curr_va = section->sh_addr + align_up(section->sh_size);
      }
    } 
   
    // Map the rest of the segment.
    if (curr_va  < size + seg.p_vaddr && 
        ioctl_mprotect_enclave(
          enclave->driver_fd,
          enclave->handle,
          dest + local_size,
          (seg.p_vaddr+ size - curr_va),
          flags,
          CONFIDENTIAL) != SUCCESS) {
       ERROR("Unable to map the rest of the enclave %lld at %llx",
           enclave->handle, curr_va);
       goto failure;
    } else if (curr_va > size + seg.p_vaddr) {
      ERROR("Mprotect overflow for enclave %lld, expected: %llx, got: %llx",
          enclave->handle, size + seg.p_vaddr, curr_va);
      goto failure;
    }
    phys_size+= size;
  } 
  DEBUG("Done mprotecting enclave %lld's sections", enclave->handle);

  // Copy the page tables + register them.
  do {
    void* source = (void*)(enclave->parser.bump.pages);
    size_t size = enclave->parser.bump.idx * PAGE_SIZE;
    uint64_t dest = enclave->parser.bump.phys_offset + enclave->map.virtoffset;
    memcpy((void*) dest, source, size); 
    
    /*// TODO remove afterwards, debugging now.
    for (int i = 0; i < enclave->parser.bump.idx; i++) {
      page_t* page = &(enclave->parser.bump.pages[i]);
      for (int j = 0; j < ENTRIES_PER_PAGE; j++) {
        uint64_t* entry = &(page->data[j]);  
        if ((*entry & PT_PP) != PT_PP) {
          continue;
        }
        DEBUG("Post copy entry: %llx @(%d, %d)", *entry, i, j);
      }
    } */

    if (ioctl_mprotect_enclave(
          enclave->driver_fd, 
          enclave->handle,
          (usize) dest,
          (usize) size,
          MEM_READ|MEM_WRITE|MEM_SUPER,
          CONFIDENTIAL) != SUCCESS) {
      ERROR("Unable to register the page tables for enclave %lld", enclave->handle);
      goto failure;
    }
    DEBUG("Done mprotecting enclave %lld's pages", enclave->handle);
  } while(0);

  // Commit the enclave.
  if (ioctl_commit_enclave(
        enclave->driver_fd,
        enclave->handle,
        enclave->config.cr3,
        enclave->config.entry,
        enclave->config.stack)!= SUCCESS) {
    ERROR("Unable to commit the enclave %lld", enclave->handle);
    goto failure;
  } 
  DEBUG("Done loading enclave %lld", enclave->handle);
  return SUCCESS;
failure:
  return FAILURE;
}

int call_enclave(enclave_t* enclave, void* args)
{
  if (enclave == NULL) {
    ERROR("The provided enclave is null.");
    goto failure;
  } 
  if (ioctl_switch_enclave(
        enclave->driver_fd,
        enclave->handle,
        args) != SUCCESS) {
    ERROR("Unable to switch to the enclave %lld", enclave->handle);
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int delete_enclave(enclave_t* enclave)
{
  if (enclave == NULL) {
    ERROR("The provided enclave is null.");
    goto failure;
  }
  // First call the driver.
  if (ioctl_delete_enclave(enclave->driver_fd, enclave->handle) != SUCCESS) {
    ERROR("Unable to delete the enclave %lld", enclave->handle);
    goto failure;
  }
  // Now collect everything else.
  // The config.
  while (!dll_is_empty(&(enclave->config.shared_sections))) {
    enclave_shared_section_t* sec = enclave->config.shared_sections.head;
    dll_remove(&(enclave->config.shared_sections), sec, list);
    free(sec);
  }
  // The parser.
  if (unmap_parser(&(enclave->parser.bump)) != SUCCESS) {
    ERROR("Unable to munmap the bump for enclave %lld", enclave->handle);
    goto failure;
  }
  free(enclave->parser.segments);
  free(enclave->parser.sections);
  free(enclave->parser.strings);
  close(enclave->parser.fd);

  // Unmap the enclave.
  munmap((void*) enclave->map.virtoffset, enclave->map.size); 

  // Close the driver.
  close(enclave->driver_fd);
  return SUCCESS;
failure:
  return FAILURE;
}
