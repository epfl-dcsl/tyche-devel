#include "common.h"
#include "enclave_loader.h"

// ——————————————————————————————— Constants ———————————————————————————————— //

const char* ENCLAVE_PATH = "enclave";


int main(void) {
  enclave_t enclave;
  LOG("Let's load an enclave!");
  if (parse_enclave(&enclave, ENCLAVE_PATH) != SUCCESS) {
    ERROR("Unable to parse the enclave '%s'", ENCLAVE_PATH);
    goto failure;
  }

  if (load_enclave(&enclave) != SUCCESS) {
    ERROR("Unable to load the enclave '%s'", ENCLAVE_PATH);
    goto failure;
  }

  return  0;
failure:
  return FAILURE;
}
