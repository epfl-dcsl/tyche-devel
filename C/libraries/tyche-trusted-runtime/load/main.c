#include "common.h"
#include "sdk_tyche.h"
#include <stdint.h>

/// Looks up for the shared memory region with the enclave.
static void* find_default_shared(tyche_domain_t* enclave)
{
  domain_shared_memory_t* shared_sec = NULL;
  if (enclave == NULL) {
    ERROR("Supplied enclave is null.");
    goto failure;
  }
  // Find the shared region.
  dll_foreach(&(enclave->config.shared_regions), shared_sec, list) {
      if (shared_sec->segment->p_type == KERNEL_SHARED 
          && shared_sec->segment->p_vaddr == 0x300000) {
        LOG("Shared section: host(%llx), guest(%llx)",
            shared_sec->untrusted_vaddr, 0x300000);
        return (void*)(shared_sec->untrusted_vaddr);
      }
  }
  ERROR("Unable to find the shared buffer for the enclave!");
failure:
  return NULL;
}

int main(int argc, char* argv[])
{
  tyche_domain_t enclave;
  LOG("Loading enclave");
  if (sdk_create_domain(
        &enclave, argv[0], 1, 1, DEFAULT_PERM, CopyVCPU) != SUCCESS) {
    ERROR("Unable to parse the enclave");
    goto failure;
  }

  /// Call the enclave a first time.
  uint64_t* shared = (uint64_t*) find_default_shared(&enclave);
  LOG("About to call the enclave");
  if (sdk_call_domain(&enclave, NULL) != SUCCESS) {
    ERROR("Unable to call the enclave %lld", enclave.handle);
  } else {
    /// We survived one call!
    LOG("Survived a call to the enclave!");
  }
  if (*shared == 666) {
    LOG("The runtime managed to write the value!");
   } else {
    LOG("The div by 0 never happened %llx.", *shared);
   }

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
