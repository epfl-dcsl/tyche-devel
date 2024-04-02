#define _GNU_SOURCE
#include "common.h"
#include "common_log.h"
#include "backend.h"
#include "sdk_tyche.h"
#include "sdk_tyche_rt.h"
#include "tyche_driver.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#define ATTESTATION_BUFFER_SIZE 2048

// —————————————————————————————————— Main —————————————————————————————————— //

int main(int argc, char *argv[]) {
  char buff[ATTESTATION_BUFFER_SIZE];
  attest_buffer_t buff_info;

  // Open Tyche driver
  int tyche = open(DOMAIN_DRIVER, O_RDWR);
  if (tyche < 0) {
    ERROR("Could not open Tyche driver");
    goto failure;
  }
  
  // Prepare arguments and call into Tyche
  buff_info.start = (unsigned long)&buff[0];
  buff_info.size = ATTESTATION_BUFFER_SIZE;
  buff_info.written = 0;
  if(ioctl(tyche, TYCHE_GET_ATTESTATION, &buff_info) != SUCCESS) {
    ERROR("Tyche driver returned and error while serializing the attestation");
    goto failure;
  }

  if (buff_info.written > 0) {
    // Write the content to the standard output
    fwrite(buff, sizeof(char), buff_info.written, stdout);
  } else {
    ERROR("No bytes written in the attestation");
    goto failure;
  }


  return SUCCESS;
failure:
  return FAILURE;
}
