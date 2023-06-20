#include <stdlib.h>

#include "common.h"
#include "enclave_loader.h"
#include "sdk_app.h"

int sdk_create_enclave(
    enclave_t* encl,
    char* default_path,
    const char* self,
    char** loaded_enclave,
    usize cores,
    usize traps)
{
  // Select whether we have a tychools instrumented binary.
  int extract = getenv(ENCL_INCL) != NULL; 

  // The environment variable overwrites the default enclave path.
  char* encl_file = getenv(ENCL_BIN);
  encl_file = (encl_file == NULL)? default_path : encl_file;

  // Is the binary already instrumented with page tables by tychools?
  int tychools = getenv(TYCHOOLS) != NULL;

  if (encl_file == NULL) {
    ERROR("No enclave selected");
    goto failure;
  }
  if (extract && self == NULL) {
    ERROR("Program name required to extract the enclave ELF!");
    goto failure;
  }
  // We need to extract the enclave from the current binary.
  if (extract && extract_enclave(self, encl_file) != SUCCESS) {
    ERROR("Error extracting the enclave ELF from the current binary.");
    goto failure;
  } 

  // The binary is already instrumented, let's load it.
  // TODO expose cores and traps.
  if (tychools && tychools_init_enclave_with_cores_traps(
        encl, encl_file, cores, traps) != SUCCESS) {
    ERROR("Unable to load tychools binary %s", encl_file);
    goto failure;
  } else if (!tychools && init_enclave_with_cores_traps(
        encl, encl_file, cores, traps) != SUCCESS) {
    ERROR("Unable to load uninstrumented binary %s", encl_file);
    goto failure;
  }
  // All done!
  if (loaded_enclave != NULL) {
      *loaded_enclave = encl_file;
  }
  return SUCCESS;
failure:
  return FAILURE;
}
