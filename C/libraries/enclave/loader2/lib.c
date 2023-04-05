#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "pts.h"
#include "common.h"
#include "enclave_loader.h"

int parse_enclave(enclave_t* enclave, const char* file)
{
  int encl_fd = -1;
  size_t segments_size = 0;
  Elf64_Ehdr hdr = {0};
  Elf64_Phdr *segments = NULL;

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
  encl_fd = open(file, O_RDONLY);
  if (encl_fd < 0) {
    ERROR("Could not open '%s': %d", file, errno);
    goto failure;
  }

  // Parse the ELF.
  read_elf64_header(encl_fd, &hdr);
  read_elf64_segments(encl_fd, hdr, &segments); 

  // Compute the entire size of all segments.
  for (int i = 0; i < hdr.e_phnum; i++) {
    segments_size += align_up(segments[i].p_memsz);
  }
  if (segments_size % PAGE_SIZE != 0) {
    ERROR("The computed size for the segments is %zu", segments_size);
    goto close_failure;
  }
  DEBUG("The overall size for the binary is %zu", segments_size);

  // Create the page tables.

close_failure:
  close(encl_fd);
failure:
  return FAILURE;
}
