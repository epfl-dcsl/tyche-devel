#include <fcntl.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>

// elf64 library includes.
#include "elf64.h"
// local includes.
#include "encl_loader.h"
// Tyche API for vmcall_frame_t.
#include "tyche_api.h"
#include "tyche_capabilities_types.h"

// ———————————————————————————————— Logging ————————————————————————————————— //

#define LOG(...) \
  do { \
    fprintf(stderr, "[encl_loader] @%s :", __func__); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
  } while(0);

// ——————————————————————————————— Constants ———————————————————————————————— //
const char* STACK_SECTION_NAME = ".encl_stack";
char* ENCLAVE_START = "encl_start";
const uint64_t stack_headroom = 4;
const char* ENCL_DRIVER = "/dev/tyche_enclave"; 
static lib_encl_t* library_plugin = NULL;


// ——————————————————————————— Internal Functions ——————————————————————————— //

void* mmap_file(const char* file, int* fd, size_t* size)
{
  if (fd  == NULL || size == NULL) {
    LOG("fd or size is NULL.\n");
    goto fail;
  }
  // First open the file.
  *fd = open(file, O_RDONLY);
  if (*fd < 0) {
    LOG("Unable to open file '%s'\n", file);
    goto fail;
  }

  // Now mmap the file.
  struct stat s;
  int status = fstat(*fd, &s);
  if (status < 0) {
    LOG("Unable to stat file '%s'\n", file);
    goto fail_close;
  } 
  void* ptr = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, *fd, 0); 
  if (ptr == MAP_FAILED) {
    LOG("mmap failed for size %d\n", s.st_size);
    goto fail_close;
  }
  // Set the size.
  *size = s.st_size;
  // Success.
  return ptr;

  // Failure.
fail_close:
  close(*fd);
fail:
  return NULL;
}

/// Parses the enclave's ELF.
int parse_enclave(load_encl_t* encl)
{
  if (encl == NULL || encl->elf_fd < 0) {
    LOG("enclave is null or missing elf fd\n");
    return -1;
  }
  // Header
  read_elf64_header(encl->elf_fd, &(encl->header));
  
  // Segments to map.
  read_elf64_segments(encl->elf_fd, encl->header, &(encl->segments));
  
  // Sections: find the stack.
  // Later we can use that part to divide kernel vs. user code too.
  read_elf64_sections(encl->elf_fd, encl->header, &(encl->sections));
  char *sh_names = read_section64(encl->elf_fd, encl->sections[encl->header.e_shstrndx]); 
  for (int i = 0; i < encl->header.e_shnum; i++) {
    if (strcmp(sh_names + encl->sections[i].sh_name, STACK_SECTION_NAME) == 0) {
      encl->stack_section = &(encl->sections[i]);
      break;
    } 
  }
  free(sh_names);
  sh_names = NULL;
  // Do this the clean way. For now, let's just have a variable. 
  if(encl->stack_section == NULL) {
    LOG("no stack section.\n");
    goto fail;
  }
  
  // Find the entry point.
  encl->entry_point = find_symbol(encl->elf_fd, ENCLAVE_START, encl->header, encl->sections);

  // All went well
  return 0;
fail:
  free(encl->sections);
  free(encl->segments);
  return -1;
}

static uint64_t translate_elf_flags(Elf64_Word flags) {
  //TODO reenable once we have a kernel.
  uint64_t result = 0;//TE_USER;
  if (flags & PF_X) {
    result |= TE_EXEC; 
  }
  if (flags & PF_W) {
    result |= TE_WRITE;
  }
  if (flags & PF_R) {
    result |= TE_READ;
  }
  return result;
}

int map_enclave(load_encl_t* enclave)
{
  if (enclave == NULL) {
    LOG("enclave is NULL.\n");
    goto fail;
  }

  // Allocate the tracker for each segment mapping.
  enclave->mappings = calloc(sizeof(void*), enclave->header.e_phnum);
  if (enclave->mappings == NULL) {
    LOG("mappings are NULL.\n");
    goto fail;
  }
  enclave->sizes = calloc(sizeof(size_t), enclave->header.e_phnum);
  if (enclave->sizes == NULL) {
    LOG("sizes are NULL.\n");
    goto fail_free;
  }
  // Set all the mappings to NULL.
  for (int i = 0; i < enclave->header.e_phnum; i++) {
    enclave->mappings[i] = NULL;
  }

  // Map each segment.
  for (int i = 0; i < enclave->header.e_phnum; i++) {
    Elf64_Phdr segment = enclave->segments[i]; 
    uint64_t flags = 0;

    // Non-loadable segments are ignored.
    if (segment.p_type != PT_LOAD) {
      continue;
    } 

    // Align up if needed.
    size_t modulo = (size_t) (segment.p_memsz % segment.p_align);
    enclave->sizes[i] = segment.p_memsz + (modulo != 0) * (segment.p_align - modulo); 
    enclave->mappings[i] = mmap(NULL, enclave->sizes[i], PROT_READ|PROT_WRITE, 
        MAP_PRIVATE|MAP_POPULATE|MAP_ANONYMOUS, -1, 0);
    if (enclave->mappings[i] == MAP_FAILED) {
      LOG("map failed.\n");
      goto fail_unmap;
    }

    // Copy the content from file  + offset.
    memcpy(enclave->mappings[i],
        enclave->elf_content + segment.p_offset, segment.p_filesz);
  }
  return 0;

  // Errors.
fail_unmap:
  for (int i = 0; i < enclave->header.e_phnum; i++) {
    if (enclave->mappings[i] == NULL || enclave->mappings[i] == MAP_FAILED) {
      continue;
    }
    munmap(enclave->mappings[i], enclave->sizes[i]);
  }
  free(enclave->sizes);
fail_free:
  free(enclave->mappings);
fail:
  return -1;
}

int create_enclave(load_encl_t* enclave, struct tyche_encl_add_region_t* extras)
{
  enclave->driver_fd = open(ENCL_DRIVER, O_RDWR);
  if (enclave->driver_fd < 0) {
    LOG("fd invalid, errno: %d\n", errno);
    goto fail;
  }

  // Create the enclave.
  struct tyche_encl_create_t create;
  if (ioctl(enclave->driver_fd, TYCHE_ENCLAVE_CREATE, &create) == -1) {
    LOG("ioctl call failed.\n");
    goto fail_close;
  }
  // Set the handle.
  enclave->handle = create.handle;
 
  if (enclave->mappings == NULL) {
    LOG("create_enclave mappings is null.\n");
    goto fail_close;
  }
  if (enclave->sizes == NULL) {
    LOG("create_enclave sizes is null.\n");
    goto fail_close;
  }

  // Add the encl.so to the enclave.
  do {
    struct tyche_encl_add_region_t region = {
      .handle = enclave->handle,
      .start = (uint64_t)library_plugin->plugin,
      .end = ((uint64_t)(library_plugin->plugin)) + library_plugin->size,
      .src = (uint64_t)library_plugin->plugin,
      .flags = TE_READ|TE_EXEC|TE_SUPER,
      .tpe = SHARED,
    };
    if (ioctl(enclave->driver_fd, TYCHE_ENCLAVE_ADD_REGION, &region) != 0) {
      LOG("create_enclave unable to add encl.so region.\n");
      goto fail_free;
    }

  } while(0);

  // Add the extras too.
  do {
    struct tyche_encl_add_region_t* curr = NULL;
    for (curr = extras; curr != NULL; curr = (struct tyche_encl_add_region_t*)curr->extra) {
      curr->handle = enclave->handle;
      if (ioctl(enclave->driver_fd, TYCHE_ENCLAVE_ADD_REGION, curr) !=0) {
        LOG("create_enclave failed to add extras.\n");
        goto fail_free;
      }
    }
  } while(0);

  // Load each segment.
  for (int i = 0; i < enclave->header.e_phnum; i++) {
    Elf64_Phdr segment = enclave->segments[i]; 
    uint64_t flags = 0;

    // Non-loadable segments are ignored.
    if (segment.p_type != PT_LOAD) {
      continue;
    } 
    // Translate the flags.
    flags = translate_elf_flags(segment.p_flags);
    struct tyche_encl_add_region_t region = {
      .handle = enclave->handle,
      .start = segment.p_vaddr, //TODO this will depend on the elf type.
      .end = segment.p_vaddr + enclave->sizes[i],
      .src = (uint64_t)enclave->mappings[i],
      .flags = flags|TE_SUPER,
      .tpe = CONFIDENTIAL,
    };
    // Call the driver with segment.p_vaddr, p_vaddr + pmemsz, p_flags
    if(ioctl(enclave->driver_fd, TYCHE_ENCLAVE_ADD_REGION, &region) != 0) {
      LOG("create_enclave failed to add region.\n");
      goto fail_unmap;
    }
  }

  // Now commit.
  struct tyche_encl_commit_t commit = {
    .handle = enclave->handle,
    .domain_handle = 0,
  };
  if (enclave->stack_section != NULL) {
    Elf64_Shdr* stack = enclave->stack_section;
    commit.stack = (uint64_t)(stack->sh_addr + stack->sh_size - stack_headroom); 
  }
  if (enclave->entry_point != NULL) {
    commit.entry = enclave->entry_point->st_value;
  }
  if (ioctl(enclave->driver_fd, TYCHE_ENCLAVE_COMMIT, &commit) != 0) {
    LOG("create_enclave failed to commit.\n");
    goto fail_unmap;
  }
  if (commit.handle != enclave->handle) {
    LOG("create_enclave commit handle is not enclave handle\n");
    goto fail_unmap;
  }
  // Setup the domain handle.
  enclave->domain_handle = commit.domain_handle;
  // Everything went well.
  return 0;

  // Errors.
fail_unmap:
  for (int i = 0; i < enclave->header.e_phnum; i++) {
    if (enclave->mappings[i] == NULL || enclave->mappings[i] == MAP_FAILED) {
      continue;
    }
    munmap(enclave->mappings[i], enclave->sizes[i]);
  }
  free(enclave->sizes);
fail_free:
  free(enclave->mappings);
fail_close:
  close(enclave->driver_fd);
fail:
  return -1;
}

//TODO change this, replace with a mapping of the lib.
const lib_encl_t* init_enclave_loader(const char* libencl)
{
  if (library_plugin != NULL) {
    return library_plugin;
  }
  int fd = open(libencl, O_RDONLY);
  if (fd < 0) {
    LOG("unable to open libencl '%s'.\n", libencl);
    goto fail;
  }
  Elf64_Ehdr header; 
  read_elf64_header(fd, &header);

  Elf64_Phdr* segments = NULL;
  read_elf64_segments(fd, header, &segments);
  
  // Find the .text section.
  Elf64_Shdr* sections = NULL;
  read_elf64_sections(fd, header, &sections);
  char* sh_names = read_section64(fd, sections[header.e_shstrndx]); 
  Elf64_Shdr* text = NULL;
  int text_idx = -1;
  Elf64_Phdr* text_seg = NULL;
  for (int i = 0; i < header.e_shnum; i++) {
    if (strcmp(".text", sh_names + sections[i].sh_name) == 0) {
      text = &sections[i];
      text_idx = i;
      break;
    }
  }
  free(sh_names);
  if (!text)
  {
    LOG("unable to find text section in libencl.\n");
    goto fail_close;
  }

  // Find the correct segment.
  for (int i = 0; i < header.e_phnum; i++) {
    if (segments[i].p_offset <= text->sh_offset 
        && ((segments[i].p_offset +segments[i].p_filesz) >= text->sh_offset + text->sh_size)) {
      text_seg = &segments[i];
      break;
    }
  } 
  if(text_seg == NULL) {
    LOG("no text segment found.\n");
    goto fail_close;
  }
  
  library_plugin = malloc(sizeof(lib_encl_t));
  if (!library_plugin) {
    LOG("library allocation failed.\n");
    goto fail_close;
  }

  // Mmap the segment.
  library_plugin->size = (text_seg->p_memsz) + ((text_seg->p_memsz % text_seg->p_align) != 0) 
    * (text_seg->p_align - (text_seg->p_memsz % text_seg->p_align));
  library_plugin->plugin = mmap(NULL, library_plugin->size, PROT_READ|PROT_WRITE,
      MAP_ANONYMOUS|MAP_PRIVATE|MAP_POPULATE |MAP_FILE, -1, 0);
  if (library_plugin->plugin == MAP_FAILED) {
    LOG("mapping plugin failed.\n");
    goto fail_free;
  }

  // Copy the content
  if (lseek(fd, text_seg->p_offset, SEEK_SET) != text_seg->p_offset) {
    LOG("seeking text segment offset failed.\n");
    goto fail_unmap;
  }

  if(read(fd, library_plugin->plugin, text_seg->p_filesz) != text_seg->p_filesz) {
    LOG("reading text segment failed.\n");
    goto fail_unmap;
  }
  
  // Now mprotect.
  mprotect(library_plugin->plugin, library_plugin->size, PROT_READ|PROT_EXEC);

  close(fd);
  // All good, return the plugin.
  return library_plugin; 

fail_unmap:
  munmap(library_plugin->plugin, library_plugin->size);
fail_free:
  free(library_plugin);
  library_plugin = NULL;
fail_close:
  close(fd);
fail:
  return NULL;
}

// ——————————————————————————————— Public API ——————————————————————————————— //

int load_enclave( const char* file,
                  load_encl_t* enclave, 
                  struct tyche_encl_add_region_t* extras)
{
  // You need to initialize the library_plugin
  if (!library_plugin) {
    LOG("library_plugin is null.\n");
    goto fail;
  }

  if (enclave == NULL) {
    LOG("enclave structure is NULL.\n");
    goto fail;
  }
  memset(enclave, 0, sizeof(load_encl_t));
  // mmap the file in memory.
  enclave->elf_content = mmap_file(file, &(enclave->elf_fd), &(enclave->elf_size));
  if (enclave->elf_content == NULL || enclave->elf_fd == -1) {
    LOG("mmap of enclave failed.\n");
    goto fail; 
  }

  // Parse the ELF file.
  if (parse_enclave(enclave) != 0) {
    LOG("unable to parse enclave.\n");
    goto fail_close;
  }

  if (map_enclave(enclave) != 0) {
    LOG("unable to map the enclave.\n");
    goto fail_free;
  }

  // Create the enclave.
  if (create_enclave(enclave, extras) != 0) {
    LOG("create enclave failure.\n");
    goto fail_free; 
  }
  
  // Unmap the file.
  if(munmap(enclave->elf_content, enclave->elf_size) != 0) {
    LOG("Failed to unmap.\n");
    goto fail_free;
  }
  if (close(enclave->elf_fd) != 0) {
    LOG("Failed to close the elf fd.\n");
    goto fail_free;
  }
  enclave->elf_content = NULL;
  enclave->elf_size = 0;

  return 0;
fail_free:
  free(enclave->sections);
  free(enclave->segments);
fail_close:
  close(enclave->elf_fd);
fail:
  return -1;
}

int delete_enclave(load_encl_t* encl)
{
  if (encl == NULL) {
    LOG("null handle.\n");
    return -1;
  } 

  if (ioctl(encl->driver_fd, TYCHE_ENCLAVE_DELETE, encl->handle) != 0) {
    LOG("delete_enclave failure from the driver.");
    return -1;
  }
  
  // Cleaning up the structure.
  free(encl->sections);
  free(encl->segments);
  encl->stack_section = NULL;
  free(encl->entry_point); 
  for (int i = 0; i < encl->header.e_phnum; i++) {
    munmap(encl->mappings[i], encl->sizes[i]);
  }
  free(encl->mappings);
  free(encl->sizes);
  encl->mappings = NULL;
  encl->sizes = NULL;
  return 0;
}

int enclave_driver_transition(domain_id_t id, void* args)
{
  struct tyche_encl_switch_t sw = {id, args};
  int driver_fd = open(ENCL_DRIVER, O_RDWR);
  if (driver_fd < 0) {
    LOG("create_enclave fd invalid %d\n", errno);
    return -1;
  }

  int ret = ioctl(driver_fd, TYCHE_TRANSITION, &sw);
  if (ret != 0) {
    LOG("driver refused transition: %d\n", ret);
    return -1;
  }
  close(driver_fd);
  return 0;
}

int enclave_user_switch(domain_id_t handle, void* args)
{
  usize arg_n = (usize) args;
  usize result = FAILURE; 
  usize vmcall = TYCHE_SWITCH;
  asm volatile(
    "movq %1, %%rax\n\t"
    "movq %2, %%rdi\n\t"
    "movq %3, %%rsi\n\t"
    "movq %4, %%r11\n\t"
    "vmcall\n\t"
    "movq %%rax, %0\n\t"
    : "=rm" (result)
    : "rm" (vmcall), "rm" (handle), "rm" (NO_CPU_SWITCH), "rm" (arg_n)
    : "rax", "rdi", "rsi", "r11", "memory"
      );
  return (int) result;
}
