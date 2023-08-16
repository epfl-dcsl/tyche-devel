#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "elf64.h"
#include "driver_ioctl.h"
#include "tyche_capabilities_types.h"
#if defined(CONFIG_X86) || defined(__x86_64__)
#include "x86_64_pt.h"
#elif defined(CONFIG_RISCV) || defined(__riscv)
#include "riscv48_pt.h"
#endif
#include "common.h"
#include "sdk_tyche_rt.h"
#include "sdk_tyche.h"

// ———————————————————————————— Local Functions ————————————————————————————— //
static uint32_t PF_H = 1 << 3;
/// Translate ELF flags into tyche memory access rights.
static memory_access_right_t translate_flags_to_tyche(Elf64_Word flags) {
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
  if((flags & PF_H) == PF_H) {
    ERROR("ATTESTATION RIGHT");
    rights |= MEM_HASH;
  }
  //TODO do user?
  rights |= MEM_SUPER;
  return rights;
}

/// Determines whether a segment type is confidential.
static int is_confidential(tyche_phdr_t tpe)
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

/// Determines whether a segment type is loadable.
static int is_loadable(tyche_phdr_t tpe)
{
    if (tpe < USER_STACK_SB || tpe > KERNEL_CONFIDENTIAL) {
      return 0;
    }
    return 1;
}

static addr_t align_up(addr_t addr)
{
  if (addr % PT_PAGE_SIZE == 0) {
    return addr;
  }
  return (addr + PT_PAGE_SIZE) & ~(PT_PAGE_SIZE-1); 
}

/// Look for the domain binary inside the current program's binary.
/// If destf is not null, it writes the extracted binary to the specified file.
static int extract_binary(elf_parser_t* parser, const char* self, const char* destf)
{
  void* dest = NULL;
  Elf64_Ehdr header;
  Elf64_Shdr* sections = NULL;
  Elf64_Shdr* domain_elf = NULL; 
  if (parser == NULL || self == NULL) {
    ERROR("Null argument: parser(%p), self(%p)", parser, self);
    goto failure;
  }
  memset(parser, 0, sizeof(elf_parser_t));

  parser->fd = open(self, O_RDONLY); 
  parser->type = FILE_ELF;
  if (parser->fd < 0) {
    ERROR("Failed to read self(%s)", self);
    goto failure;
  }
  // Read the header.
  read_elf64_header(parser, &header);
  
  // Read the sections.
  read_elf64_sections(parser, header, &sections);

  // Find the section for the domain.
  domain_elf = &sections[header.e_shnum-1];
  if (domain_elf->sh_type != SHT_NOTE) {
    ERROR("Wrong section type for domain");
    goto failure_free_sec;
  } 
  if (domain_elf == NULL) {
    ERROR("Unable to find the domain ELF section.");
    goto failure_free_sec;
  }
  
  // Now load the section.
  dest = read_section64(parser, *domain_elf); 
  if (dest == NULL) {
    ERROR("Unable to mmap memory for the domain ELF");
    goto failure_free_sec;
  }

  // If destf specified, dump it into the destination file.
  if (destf != NULL) {
    FILE* dest_file = fopen(destf, "wb");
    if (dest_file != NULL) {
      size_t written = fwrite(dest, 1, domain_elf->sh_size, dest_file);
      if (written != domain_elf->sh_size) {
        ERROR("Failed to write all the domain ELF bytes");
        fclose(dest_file);
        goto failure_free;
      } 
      fclose(dest_file);
    } else {
      ERROR("Failed to open destf(%s)", destf);
      goto failure_free;
    }
  }

  // Update the parser with the domain.
  close(parser->fd);
  parser->type = MEM_ELF;
  parser->memory.start = (char*) dest;
  parser->memory.offset = 0;
  parser->memory.size = domain_elf->sh_size;

  // Cleanup.
  free(sections);
  return SUCCESS;
failure_free:
  free(dest);
failure_free_sec:
  free(sections);
failure:
  return FAILURE;
}

// —————————————————————————— Prototype functions ——————————————————————————— //

/// Calls both parse and load domain pointed by the file.
int init_domain_with_cores_traps(
    tyche_domain_t* domain,
    usize cores,
    usize traps,
    usize perms,
    switch_save_t switch_type);

/// Parses an ELF binary created by tychools.
/// All the segments for the domain should have OS-specific types.
/// The page tables must be present, as well as the stacks and shared regions.
int parse_domain(tyche_domain_t* domain);

/// Loads an domain created with tychools.
/// It patches the page tables that should be located inside one of the segments.
int load_domain(tyche_domain_t* domain);

// ——————————————————————————————— Functions ———————————————————————————————— //

int init_domain_with_cores_traps(
    tyche_domain_t* domain,
    usize cores,
    usize traps,
    usize perms,
    switch_save_t switch_type)
{
  if (domain == NULL || domain->parser.elf.memory.start == NULL) {
    ERROR("Null argument provided: domain(%s)", domain);
    goto failure;
  }
  domain->traps = traps;
  domain->core_map = cores;
  domain->perms = perms;
  domain->switch_type = switch_type;
  if (parse_domain(domain) != SUCCESS) {
    ERROR("Unable to parse the domain");
    goto failure;
  }
  if (load_domain(domain) != SUCCESS) {
    ERROR("Unable to load the domain");
    goto failure;
  }
  // All done!
  return SUCCESS;
failure:
  return FAILURE;
}

int parse_domain(tyche_domain_t* domain)
{
  size_t segments_size = 0;

  // Common checks.
  if (domain == NULL) {
    ERROR("domain structure is null."); 
    goto failure;
  }
  if (domain->parser.elf.memory.start == NULL) {
    ERROR("The domain's memory content is null.");
    goto failure;
  }
  dll_init_list(&(domain->config.shared_regions));
  
  // Parse the ELF.
  read_elf64_header(&domain->parser.elf, &(domain->parser.header));
  read_elf64_segments(&domain->parser.elf,
      domain->parser.header, &(domain->parser.segments)); 
  //@note: We do not need to parse the sections as tychools works on segments. 

  // Set up the entry point.
  domain->config.entry = domain->parser.header.e_entry;

  // Find the stack and the shared regions.
  for (int i = 0; i < domain->parser.header.e_phnum; i++) {
    Elf64_Phdr* segment = &domain->parser.segments[i];
    // Found the user stack.
    if (segment->p_type == USER_STACK_SB || segment->p_type == USER_STACK_CONF) {
      domain->config.user_stack = segment->p_vaddr + segment->p_memsz - STACK_OFFSET_TOP; 
    }
    // Found the kernel stack.
    if (segment->p_type == KERNEL_STACK_SB || segment->p_type == KERNEL_STACK_CONF) {
      domain->config.stack = segment->p_vaddr + segment->p_memsz - STACK_OFFSET_TOP;
    }
    // Found a shared segment.
    if (segment->p_type == KERNEL_SHARED || segment->p_type == USER_SHARED) {
      domain_shared_memory_t *shared = malloc(sizeof(domain_shared_memory_t));
      if (shared == NULL) {
        ERROR("Unable to malloc domain_shared_memory_t");
        goto failure;
      } 
      memset(shared, 0, sizeof(domain_shared_memory_t));
      shared->segment = segment;
      dll_init_elem(shared, list);
      dll_add(&(domain->config.shared_regions), shared, list);
    }
    // Found the page tables.
    if (segment->p_type == PAGE_TABLES_SB || segment->p_type == PAGE_TABLES_CONF) {
      domain->config.cr3 = segment->p_vaddr;
      //TODO figure out if we want to keep a pointer to the segment.
    }
  }
  
  // Compute the entire size of all segments.
  for (int i = 0; i < domain->parser.header.e_phnum; i++) {
    Elf64_Word tpe = domain->parser.segments[i].p_type;
    // Only consider loadable segments instrumented by tychools.
    if (!is_loadable(tpe)) {
      continue;
    }
    segments_size += align_up(domain->parser.segments[i].p_memsz);
  }
  if (segments_size % PT_PAGE_SIZE != 0) {
    ERROR("The computed size for the segments is %zu", segments_size);
    goto close_failure;
  }
  DEBUG("The overall size for the binary is %zx", segments_size);
  domain->map.size = segments_size;
  
  // We are done for now, next step is to load the domain.
  LOG("Parsed tychools binary");
  return SUCCESS;
close_failure:
  free(domain->parser.elf.memory.start);
  domain->parser.elf.memory.start = NULL;
failure:
  return FAILURE;
}

int load_domain(tyche_domain_t* domain)
{
  usize size = 0;
  usize phys_size = 0;
  if (domain == NULL) {
    ERROR("The domain is null.");
    goto failure;
  }

  if (domain->parser.segments == NULL) {
    ERROR("The domain is not parsed. Call parse_domain first!");
    goto failure;
  }

  // Open the driver.
  domain->handle = open(DOMAIN_DRIVER, O_RDWR);
  if (domain->handle < 0) {
    ERROR("Unable to create an domain with open %s", DOMAIN_DRIVER);
    goto failure;
  }

  // Mmap the size of memory we need.
  if (ioctl_mmap(
        domain->handle,
        domain->map.size,
        &(domain->map.virtoffset)) != SUCCESS) {
    goto failure;
  }
  
  // Get the physoffset.
  if (ioctl_getphysoffset(
        domain->handle,
        &(domain->map.physoffset)) != SUCCESS) {
    goto failure;
  }

  // Add the offset to the domain's cr3.
  domain->config.cr3 += domain->map.physoffset;
  DEBUG("The domain's cr3 is at %llx", domain->config.cr3);

  // Copy the domain's content.
  phys_size = 0;
  for (int i = 0; i < domain->parser.header.e_phnum; i++) {
    Elf64_Phdr seg = domain->parser.segments[i];
    // The segment is not loadable.
    if (!is_loadable(seg.p_type)) {
      continue;
    }
    addr_t dest = domain->map.virtoffset + phys_size;
    addr_t size = align_up(seg.p_memsz);
    memory_access_right_t flags = translate_flags_to_tyche(seg.p_flags);
    load_elf64_segment(&domain->parser.elf, (void*) dest, seg);

    // If segment is shared, fix it in the shared_segments.
    // For now, do it in a non-efficient way.
    domain_shared_memory_t* shared =  NULL;
    dll_foreach(&(domain->config.shared_regions), shared, list) {
      if (shared->segment->p_vaddr == seg.p_vaddr) {
          shared->untrusted_vaddr = dest;
      }
    }

    // Fix the page tables here.
    if (seg.p_type == PAGE_TABLES_CONF || seg.p_type == PAGE_TABLES_SB) {
      uint64_t* start = (uint64_t*) dest;
      uint64_t* end = (uint64_t*)(((uint64_t) dest) + size);
      for (; start < end; start++) {
        if (*start != 0) {
          *start += domain->map.physoffset;
        }
      } 
    }

    // Now map the segment.
    int conf_or_shared = is_confidential(seg.p_type)? CONFIDENTIAL : SHARED; 
    if (conf_or_shared == CONFIDENTIAL) {
      flags |= MEM_CONFIDENTIAL;
    }
    if (ioctl_mprotect(
          domain->handle,
          dest,
          size,
          flags,
          conf_or_shared) != SUCCESS) {
      ERROR("Unable to map segment for domain %d at %llx",
          domain->handle, dest);
      goto failure;
    }
    // Update the current size.
    phys_size+= size;
  } 
  DEBUG("Done mprotecting domain %d's sections", domain->handle);

  // Set the cores and traps.
  if (ioctl_set_traps(domain->handle, domain->traps) != SUCCESS) {
    ERROR("Unable to set the traps for the domain %d", domain->handle);
    goto failure;
  }
 
  if (ioctl_set_cores(domain->handle, domain->core_map) != SUCCESS) {
    ERROR("Unable to set the cores for the domain %d", domain->handle);
    goto failure;
  }

  // TODO(aghosn) expose this through the SDK.
  // I don't do it now because I'll need some time to refactor libraries to avoid
  // having so many layers of forwarding. It's becoming really annoying.
  if (ioctl_set_perms(domain->handle, domain->perms) != SUCCESS) {
    ERROR("Unable to set the permission on domain %d", domain->handle);
    goto failure;
  }

  // TODO(aghosn) same as above.
  if (ioctl_set_switch(domain->handle, domain->switch_type) != SUCCESS) {
      ERROR("Unable to set the switch type.");
      goto failure;
  } 

  // TODO(aghosn) same as above as well.
  if (ioctl_set_entry_on_core(
        domain->handle,
        0,
        domain->config.cr3,
        domain->config.entry,
        domain->config.stack) != SUCCESS) {
      ERROR("Unable to set the entry on core 0");
      goto failure;
  }

  // Commit the domain.
  if (ioctl_commit(domain->handle)!= SUCCESS) {
    ERROR("Unable to commit the domain %d", domain->handle);
    goto failure;
  } 
  DEBUG("Done loading domain %d", domain->handle);
  return SUCCESS;
failure:
  return FAILURE;
}

// ————————————————————————————— API Functions —————————————————————————————— //
int sdk_create_domain(
    tyche_domain_t* dom,
    const char* self,
    usize cores,
    usize traps,
    usize perms,
    switch_save_t switch_type)
{
  char* dump =  NULL;
  if (dom == NULL) {
    ERROR("Provided domain structure is null.");
    goto failure;
  }
  if (self == NULL) {
    ERROR("No name for the program provided.");
    goto failure;
  }
 
  // If the value is set, we will dump the extracted binary.
  dump = getenv(DUMP_BIN);
  memset(dom, 0, sizeof(tyche_domain_t));

  // We need to extract the domain from the current binary.
  if (extract_binary(&(dom->parser.elf), self, dump) != SUCCESS) {
    ERROR("Error extracting the domain ELF from the current binary.");
    goto failure;
  } 

  // The binary is already instrumented, let's load it.
  if (init_domain_with_cores_traps(
        dom, cores, traps, perms, switch_type) != SUCCESS) {
    ERROR("Unable to load tychools binary");
    goto failure;
  } 
  return SUCCESS;
failure:
  return FAILURE;
}

int sdk_call_domain(tyche_domain_t* domain, void* args)
{
  if (domain == NULL) {
    ERROR("The provided domain is null.");
    goto failure;
  } 
  if (ioctl_switch(
        domain->handle,
        args) != SUCCESS) {
    ERROR("Unable to switch to the domain %d", domain->handle);
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int sdk_delete_domain(tyche_domain_t* domain)
{
  if (domain == NULL) {
    ERROR("The provided domain is null.");
    goto failure;
  }
  // First call the driver.
  if (close(domain->handle) != SUCCESS) {
    ERROR("Unable to delete the domain %lld", domain->handle);
    goto failure;
  }
  // Now collect everything else.
  // The config.
  while (!dll_is_empty(&(domain->config.shared_regions))) {
    domain_shared_memory_t* sec = domain->config.shared_regions.head;
    dll_remove(&(domain->config.shared_regions), sec, list);
    free(sec);
  }
  free(domain->parser.segments);
  free(domain->parser.sections);
  free(domain->parser.strings);
  free(domain->parser.elf.memory.start);

  // Unmap the domain.
  munmap((void*) domain->map.virtoffset, domain->map.size); 

  return SUCCESS;
failure:
  return FAILURE;
}
