#include "common.h"
#include "enclave_loader.h"

const char* ENCLAVE_PATH = "trt";

int main(void)
{
  enclave_t enclave;
  LOG("Loading enclave");
  /// Disable divide by zero exception.
  if (init_enclave_with_cores_traps(&enclave, ENCLAVE_PATH, NO_CORES, ALL_TRAPS -1) != SUCCESS) {
    ERROR("Unable to parse the enclave: %s", ENCLAVE_PATH);
    goto failure;
  }

  /// Call the enclave a first time.
  LOG("About to call the enclave");
  if (call_enclave(&enclave, NULL) != SUCCESS) {
    ERROR("Unable to call the enclave %lld", enclave.handle);
    goto failure;
  }

  /// We survived one call!
  LOG("Survived a call to the enclave!");

  /// Clean up.
  if (delete_enclave(&enclave) != SUCCESS) {
    ERROR("Unable to delete the enclave %lld", enclave.handle);
    goto failure;
  }
  
  LOG("All done!");
  return 0;

failure:
  return FAILURE;
}
