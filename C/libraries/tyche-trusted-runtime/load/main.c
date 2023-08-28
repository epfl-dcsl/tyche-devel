#include "common.h"
#include "sdk_tyche.h"

// ———————————————————————————————— Types ————————————————————————————————— //
typedef unsigned long long ret_code_t;
#define PRINT 1001
#define GATE_CALL 1002
#define WRITE 1003
#define EXIT_GATE 107
#define EXCEPTION_CONST 111
#define DIVIDE_ZERO 222
#define RET_CODE_BYTES 8
#define TEST 1144
// ———————————————————————————————— Functions for untrusted part ————————————————————————————————— //
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
  int cnt_sys = 0;
  int exit_flag = 0;
  while(!exit_flag) {
    LOG("\nCalling enclave...");
    if (sdk_call_domain(&enclave, NULL) != SUCCESS) {
        ERROR("Unable to call the enclave %lld", enclave.handle);
        return FAILURE;
    }
    LOG("Survived call to enclave...");
    ret_code_t* shared = (ret_code_t*) find_default_shared(&enclave);
    switch(*shared) {
      case PRINT:
        LOG("PRINT syscall...");
        char* str = (char*)(shared + 1);
        LOG("print : %s", str);
        break;
      case EXIT_GATE:
        LOG("EXIT GATE");
        LOG("Num of syscalls handled %d", cnt_sys);
        exit_flag = 1;
        break;
      case DIVIDE_ZERO:
        LOG("Enclave produces DIVIDE ZERO exception, exiting...");
        exit_flag = 1;
        break;
      case GATE_CALL:
        LOG("GATE CALL");
        break;
      case WRITE:
        LOG("WRITE CALL");
        int* shared = (int*)(((char*)find_default_shared(&enclave)) + RET_CODE_BYTES);
        LOG("SHARED is %d", *shared);
        break;
      case EXCEPTION_CONST:
        LOG("Enclave produced exception, exiting...");
        exit_flag = 1;
        break;
      case TEST:
        LOG("Testing");
        unsigned long long* sharedt = (unsigned long long*)(((char*)find_default_shared(&enclave)) + RET_CODE_BYTES);
        LOG("SHARED is 0x%llx", *sharedt);
        break;
      default:
        LOG("UNKNOWN SYSCALL!!!!!!");
        exit_flag = 1;
        break;
    }
    cnt_sys++;
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
