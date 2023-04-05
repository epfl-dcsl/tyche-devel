#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "pts.h"
#include "common.h"
#include "enclave_loader.h"

// ——————————————————————————————— Constants ———————————————————————————————— //
const char* ENCLAVE_DRIVER = "/dev/tyche_enclave"; 

// ——————————————————————————————— Functions ———————————————————————————————— //

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
failure:
  return FAILURE;
}

