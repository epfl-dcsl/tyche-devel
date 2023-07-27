#include "common.h"
#include "sdk_tyche.h"

int main(void)
{
  tyche_domain_t enclave;
  LOG("Loading enclave");
  /// Disable divide by zero exception.
  if (sdk_create_domain(&enclave, NULL, NO_CORES, ALL_TRAPS -1) != SUCCESS) {
    ERROR("Unable to parse the enclave");
    goto failure;
  }

  /// Call the enclave a first time.
  LOG("About to call the enclave");
  if (sdk_call_domain(&enclave, NULL) != SUCCESS) {
    ERROR("Unable to call the enclave %lld", enclave.handle);
    goto failure;
  }

  /// We survived one call!
  LOG("Survived a call to the enclave!");

  /// Clean up.
  if (sdk_delete_domain(&enclave) != SUCCESS) {
    ERROR("Unable to delete the enclave %lld", enclave.handle);
    goto failure;
  }
  
  LOG("All done!");
  return 0;

failure:
  return FAILURE;
}
