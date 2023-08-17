#include "common.h"
#include "sdk_tyche.h"

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
        return (void*)(shared_sec->untrusted_vaddr);
      }
  }
  ERROR("Unable to find the shared buffer for the enclave!");
failure:
  return NULL;
}

int loop_calls(tyche_domain_t* enclave, const int num_of_calls) {
  for(int i = 0 ;i < num_of_calls;i++) {
    LOG("About to call the enclave");
    if (sdk_call_domain(enclave, NULL) != SUCCESS) {
      ERROR("Unable to call the enclave %lld", enclave->handle);
      return FAILURE;
    }
    LOG("Survived a call to the enclave!");
    int* shared = (int*) find_default_shared(enclave);
    LOG("SHARED IS %d!", *shared);
  }
  return SUCCESS;
}

int main(int argc, char* argv[])
{
  tyche_domain_t enclave;
  LOG("Loading enclave");
  /// Enable divide by zero exception.
  /// The code in the RT will trigger an exception if it's a div by zero it
  /// will write 666 in the shared memory buffer and return to us.
  /// If any other handler is called, it will hlt.
  if (sdk_create_domain(
        &enclave, argv[0], 1, 1, DEFAULT_PERM, CopyVCPU) != SUCCESS) {
    ERROR("Unable to parse the enclave");
    goto failure;
  }

  const int num_of_calls = 10;
  if(loop_calls(&enclave, num_of_calls) != SUCCESS) {
    goto failure;
  }  

  LOG("\nFinished loop calls! Domain call to catch an interrupt");
  if (sdk_call_domain(&enclave, NULL) != SUCCESS) {
      ERROR("Unable to call the enclave %lld", enclave.handle);
      return FAILURE;
  }
  LOG("Survived a call to the enclave!");
  int* shared = (int*) find_default_shared(&enclave);
  LOG("SHARED IS %d!", *shared);


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
