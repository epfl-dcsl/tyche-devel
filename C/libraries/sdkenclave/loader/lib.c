#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "elf64.h"
#include "driver_ioctl.h"
#include "pts.h"
#include "common.h"
#include "enclave_loader.h"

// ——————————————————————————————— Constants ———————————————————————————————— //
const char* ENCLAVE_DRIVER = "/dev/tyche_enclave"; 
const char* SHARED_PREFIX = ".tyche_shared";

// ——————————————————————————————— Functions ———————————————————————————————— //


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

  //TODO find stack and entry point.

  // Compute the entire size of all segments.
  for (int i = 0; i < enclave->parser.header.e_phnum; i++) {
    segments_size += align_up(enclave->parser.segments[i].p_memsz);
  }
  if (segments_size % PAGE_SIZE != 0) {
    ERROR("The computed size for the segments is %zu", segments_size);
    goto close_failure;
  }
  DEBUG("The overall size for the binary is %zu", segments_size);
  
  // Create the page tables.
  if (create_page_tables(
        segments_size,
        &(enclave->parser.bump),
        &(enclave->parser.header),
        enclave->parser.segments) != SUCCESS) {
    ERROR("Unable to map the page tables.");
    goto close_failure;
  }
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
  enclave->driver_fd = open(ENCLAVE_DRIVER, O_RDONLY);
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
        &(enclave->map.physoffset)) != SUCCESS) {
    goto failure;
  }

  // Fix the page tables.
  if (fix_page_tables(enclave->map.physoffset, &enclave->parser.bump) != SUCCESS) {
    ERROR("Unable to fix the page tables with the offset!");
    goto failure;
  }

  // Copy the enclave's content.
  phys_size = 0;
  for (int i = 0; i < enclave->parser.header.e_phnum; i++) {
    Elf64_Phdr seg = enclave->parser.segments[i];
    addr_t dest = enclave->map.virtoffset + phys_size;
    addr_t size = align_up(seg.p_memsz);
    addr_t local_size = 0;
    load_elf64_segment(enclave->parser.fd, (void*) dest, seg);
    addr_t curr_va = enclave->map.virtoffset;
    // Find all the sections within that segment and call the driver.
    // TODO First assume they all come sorted.
    for (int j = 0; j < enclave->parser.header.e_shnum; j++) {
      Elf64_Shdr sect = enclave->parser.sections[j]; 
      usize sect_size = align_up(sect.sh_size);
      enclave_segment_type_t tpe = get_section_tpe_from_name(
          sect.sh_name + enclave->parser.strings);  
      if (sect.sh_addr != curr_va) {
        continue; 
      }
      if (ioctl_mprotect_enclave(
            enclave->driver_fd,
            enclave->handle,
            sect.sh_addr,
            sect_size,
            translate_flags(seg.p_flags),
            tpe) != SUCCESS) {
        ERROR("Failed to mprotect the section %llx", sect.sh_addr);
        goto failure;
      }
      local_size += sect_size;
      curr_va += sect_size;
    }
    if (local_size != size) {
      ERROR("We failed to find all the sections for the segment!");
      goto failure;
    } 
    phys_size+= size;
  } 

  // Copy the page tables + register them.
  do {
    void* source = (void*)&(enclave->parser.bump.pages);
    size_t size = enclave->parser.bump.idx * PAGE_SIZE;
    uint64_t dest = enclave->parser.bump.phys_offset + enclave->map.virtoffset;
    memcpy((void*) dest, source, size); 
    if (ioctl_mprotect_enclave(
          enclave->driver_fd, 
          enclave->handle,
          (usize) dest,
          (usize) size,
          TE_READ|TE_WRITE|TE_SUPER,
          CONFIDENTIAL) != SUCCESS) {
      ERROR("Unable to register the page tables for enclave %lld", enclave->handle);
      goto failure;
    }
  } while(0);
 
failure:
  return FAILURE;
}

