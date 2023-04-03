#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <encl_loader.h>

const char* encl_so = "encl.so";
const char* trusted = "test-enclave";

static int no_module_loader(load_encl_t* enclave)
{
  enclave->elf_content = mmap_file(trusted, &(enclave->elf_fd), &(enclave->elf_size)); 
  if (enclave->elf_content == NULL || enclave->elf_fd == -1) {
    fprintf(stderr, "[encl_loader]: mmap of enclave failed.\n");
    goto fail; 
  }

  // Parse the ELF file.
  if (parse_enclave(enclave) != 0) {
    fprintf(stderr, "[encl_loader]: unable to parse enclave.\n");
    goto fail_close;
  }

  if (map_enclave(enclave) != 0) {
    fprintf(stderr, "[encl_loader]: unable to map the enclave.\n");
    goto fail_free;
  }

  return 0;
fail_free:
  free(enclave->sections);
  free(enclave->segments);
fail_close:
  close(enclave->elf_fd);
fail:
  return -1;
}


// Puts hello world inside the shared dest buffer.
void copy(void* dest)
{
  const char* message = "Hello world!\n\0";
  // Handmade memcpy.
  char* ptr = (char*) dest;
  for (int i = 0; i < 14; i++) {
    ptr[i] = message[i];
  } 
}

int main(void) {
  printf("TEST: Let's create an enclave!\n");
  const lib_encl_t* library = init_enclave_loader(encl_so);

  // mmap a shared region.
  void* shared = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_POPULATE, -1, 0);
  if (shared == MAP_FAILED) {
    fprintf(stderr, "Error mapping shared memory region.\n");
    exit(1);
  }

  load_encl_t enclave = {
    .driver_fd = 0,
    .elf_fd = 0,
    .sections = NULL,
    .segments = NULL,
    .stack_section = NULL,
  };
  no_module_loader(&enclave);
  void (*trusted_entry)(void*);
  // Let's mprotect.
  if (mprotect(enclave.mappings[3], enclave.sizes[3], PROT_READ|PROT_EXEC) != 0) {
    printf("Error mprotecting\n");
    exit(1);
  } 
  // There is a bug, it does not find the data segment correctly.
  //trusted_entry = enclave.mappings[3];
  //trusted_entry(shared);
 // library->vmcall_gate(0, enclave.mappings[3], shared);
  printf("Done with the loading. %s", shared);
  return 0;
}
