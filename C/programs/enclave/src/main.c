#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include<sys/ioctl.h>
#include <sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include <unistd.h>
#include <string.h>

// Extrernal libs.
#include <encl_loader.h>
#include <tyche_enclave.h>
#include <tyche_capabilities_types.h>

#include "my_shared.h"

const char* encl_so = "libs/encl.so";
const char* trusted = "enclave";

const char* MSG = "A message for the enlave.\n\0";

int main(void) {
  printf("Let's create an enclave!\n");
  const lib_encl_t* library = init_enclave_loader(encl_so);

  // mmap a shared region.
  void* shared = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_POPULATE, -1, 0);
  if (shared == MAP_FAILED) {
    fprintf(stderr, "Error mapping shared memory region.\n");
    exit(1);
  }
  void *sharedRO = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_POPULATE, -1, 0);
  if (sharedRO == MAP_FAILED) {
    fprintf(stderr, "Error mappin the shared read-only region.\n");
    exit(1);
  }

  // Write a message.
  memcpy(sharedRO, MSG, strlen(MSG)); 

  // Setup a struct describing the message.
  my_encl_message_t* msg = (my_encl_message_t*) shared + sizeof(enclave_entry_t);
  msg->message = sharedRO;
  msg->message_len = strlen(MSG);

  enclave_entry_t* entry = (enclave_entry_t*) shared;
  //TODO this should be extended to enable looking up symbols.
  entry->function = NULL;
  entry->args = msg;

  struct tyche_encl_add_region_t extra_ro = {
    .start = (uint64_t) sharedRO,
    .end = ((uint64_t)sharedRO)+0x1000,
    .src = (uint64_t) sharedRO,
    .flags = TE_READ|TE_SUPER,
    .tpe = SHARED,
    .extra = NULL,
  };

  // A shared region that is read-write.
  struct tyche_encl_add_region_t extra = {
    .start = (uint64_t) shared,
    .end = ((uint64_t)shared)+0x1000,
    .src = (uint64_t) shared,
    .flags = TE_READ|TE_WRITE|TE_SUPER,
    .tpe = SHARED,
    .extra = (void*)(&extra_ro),
  };

  // A shared region that is read-only.
  load_encl_t enclave;
  if (load_enclave(trusted, &enclave, &extra) != 0) {
    fprintf(stderr, "Unable to load the enclave.\n");
    exit(1);
  } 
  printf("Shared regions are %lx & %lx\n", shared, sharedRO);
  enclave_driver_transition(enclave.handle, (void*) entry);
  printf("Message from the enclave %s\n", msg->reply);
  printf("Now let's delete the enclave.\n");
  if (delete_enclave(&enclave) != 0) {
    printf("Error deleting the enclave!\n");
    return -1;
  }
  printf("Successfully delete the enclave!\n");
  return 0;
}
