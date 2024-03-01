#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "elf64.h"
#include "tyche_capabilities_types.h"
#if defined(CONFIG_X86) || defined(__x86_64__)
#include "x86_64_pt.h"
#elif defined(CONFIG_RISCV) || defined(__riscv)
#include "riscv48_pt.h"
#endif
#include "common.h"
#include "sdk_tyche_rt.h"
#include "sdk_tyche.h"
#include "backend.h"
#include "tyche_api.h"

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
    ERROR("Null argument provided: domain(%p)", domain);
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
  dll_init_list(&(domain->shared_regions));
  
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
      dll_add(&(domain->shared_regions), shared, list);
    }
    // Found the page tables.
    if (segment->p_type == PAGE_TABLES_SB || segment->p_type == PAGE_TABLES_CONF) {
      domain->config.page_table_root = segment->p_vaddr;
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
  
  // Call the backend to create the domain.
  if (backend_td_create(domain) != SUCCESS) {
    ERROR("Backend error creating the backend.");
    goto failure;
  }

  // Call the backend to allocate the domain's memory.
  if (backend_td_alloc_mem(domain) != SUCCESS) {
    ERROR("Backend error allocating domain's memory.");
    goto failure;
  }

  // Add the offset to the domain's page_table_root.
  domain->config.page_table_root += domain->map.physoffset;
  DEBUG("The domain's page_table_root is at %llx", domain->config.page_table_root);

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
    dll_foreach(&(domain->shared_regions), shared, list) {
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
#if defined(CONFIG_X86) || defined(__x86_64__) 
          *start += domain->map.physoffset;
#elif defined(CONFIG_RISCV) || defined(__riscv)
          uint64_t ppn = (domain->map.physoffset >> PT_PAGE_WIDTH) + (*start >> PT_FLAGS_RESERVED);
          *start = (*start & ~PT_PHYS_PAGE_MASK) | (ppn << PT_FLAGS_RESERVED);
#endif
        }
      } 
    }

    // Now map the segment.
    int conf_or_shared = is_confidential(seg.p_type)? CONFIDENTIAL : SHARED; 
    if (conf_or_shared == CONFIDENTIAL) {
      flags |= MEM_CONFIDENTIAL;
    }
    if (backend_td_register_region(
          domain,
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

  // Set the traps.
  if (backend_td_config(
        domain, TYCHE_CONFIG_TRAPS, domain->traps) != SUCCESS) {
    ERROR("Unable to set the traps for the domain %d", domain->handle);
    goto failure;
  }
  // Set the cores. 
  if (backend_td_config(
        domain, TYCHE_CONFIG_CORES, domain->core_map) != SUCCESS) {
    ERROR("Unable to set the cores for the domain %d", domain->handle);
    goto failure;
  }
  // Set the domain permissions.
  if (backend_td_config(
        domain, TYCHE_CONFIG_PERMISSIONS, domain->perms) != SUCCESS) {
    ERROR("Unable to set the permission on domain %d", domain->handle);
    goto failure;
  }
  // Set the switch type.
  if (backend_td_config(
        domain, TYCHE_CONFIG_SWITCH, domain->switch_type) != SUCCESS) {
      ERROR("Unable to set the switch type.");
      goto failure;
  } 

  // For the moment support maximum 32 cores, 
  for (usize i = 0; i < MAX_CORES; i++) {
    // Create the core context.
    if (domain->core_map & (1ULL << i) == 0) {
      continue;
    }
    if (backend_td_create_vcpu(domain, i) != SUCCESS) {
      ERROR("Unable to create vcpu on core %lld", i); 
      goto failure;
    }
    if (backend_td_init_vcpu(domain, i) != SUCCESS) {
      ERROR("Unable to init the vcpu on core %lld", i);
    }
  }

  // Commit the domain.
  if (backend_td_commit(domain)!= SUCCESS) {
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

int sdk_call_domain(tyche_domain_t* domain, usize core)
{
  if (domain == NULL) {
    ERROR("The provided domain is null.");
    goto failure;
  } 
  if (backend_td_vcpu_run(domain, core) != SUCCESS) {
    ERROR("Unable to switch to the domain %d on core %lld", domain->handle, core);
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
  if (backend_td_delete(domain) != SUCCESS) {
    ERROR("Unable to delete the domain %d", domain->handle);
    goto failure;
  }
  // Now collect everything else.
  // The config.
  while (!dll_is_empty(&(domain->shared_regions))) {
    domain_shared_memory_t* sec = domain->shared_regions.head;
    dll_remove(&(domain->shared_regions), sec, list);
    free(sec);
  }
  free(domain->parser.segments);
  free(domain->parser.sections);
  free(domain->parser.strings);
  free(domain->parser.elf.memory.start);
  return SUCCESS;
failure:
  return FAILURE;
}
