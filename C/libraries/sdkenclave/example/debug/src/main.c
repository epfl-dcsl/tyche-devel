#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#include "common.h"
#include "driver_ioctl.h"
#include "enclave_loader.h"
#include "x86_64_pt.h"

extern void my_func(void);

__attribute__ ((aligned (0x1000)))
char attempt[0x1000];

int main(void)
{
  handle_t handle = -1;
  size_t size = 5 * PAGE_SIZE;
  usize virt_addr = 0;
  usize phys_addr = 0;
  size_t my_func_size = 35; // in bytes
  // I computed the indices by hand.
  usize dest_addr = 0x400000;
  size_t lvl4 = 0, lvl3 = 0, lvl2 = 2, lvl1 = 0;
  usize flags = PT_PP | PT_RW | PT_ACC | PT_DIRT;
  handle = open("/dev/tyche", O_RDWR);
  if (handle < 0) {
    ERROR("Unable to create an enclave");
    goto failure;
  }

  if (ioctl_mmap(handle, size, &virt_addr) != SUCCESS) {
    ERROR("Unable to mmap!");
    goto failure;
  } 

  // Zero-out everything.
  memset((void*) virt_addr, 0, size);

  if (ioctl_getphysoffset_enclave(handle, &phys_addr) != SUCCESS) {
    ERROR("Unable to get the physoffset");
    goto failure;
  }

  LOG("So far we have virt: %llx, phys: %llx", virt_addr, phys_addr);

  // Copy the function.
  memcpy((void*) virt_addr, (void*) my_func, my_func_size);

  // Do the page table now.
  page_t* root = (page_t*) (virt_addr+ PAGE_SIZE);
  root->data[lvl4] = (phys_addr + 2 * PAGE_SIZE) | flags; 
  LOG("lvl4 entry: %llx", root->data[lvl4]);

  page_t* p3_table = (page_t*) (virt_addr + 2 * PAGE_SIZE);
  p3_table->data[lvl3] = (phys_addr + 3 * PAGE_SIZE) | flags;
  LOG("lvl3 entry: %llx", p3_table->data[lvl3]);

  page_t* p2_table = (page_t*) (virt_addr + 3 * PAGE_SIZE);
  p2_table->data[lvl2] = (phys_addr + 4 * PAGE_SIZE) | flags;
  LOG("lvl2 entry: %llx", p2_table->data[lvl2]);

  page_t* p1_table = (page_t*) (virt_addr + 4 * PAGE_SIZE);
  p1_table->data[lvl1] = phys_addr | flags;
  LOG("lvl1 entry: %llx", p1_table->data[lvl1]);

  // Do the mprotect.
  if (ioctl_mprotect_enclave(
        handle,
        virt_addr,
        size,
        MEM_READ | MEM_EXEC | MEM_WRITE | MEM_SUPER,
        CONFIDENTIAL) != SUCCESS) {
    ERROR("Unable to do the mprotect.");
    goto failure;
  }
  
  // Commit.
  if (ioctl_commit_enclave(
        handle,
        phys_addr + PAGE_SIZE,
        dest_addr,
        0x6000) != SUCCESS) {
    ERROR("Unable to commit the enclave.");
    goto failure;
  }
  LOG("Done creating the enclave.");

  // Call the enclave.
  if (ioctl_switch_enclave(handle, NULL) != SUCCESS) {
    ERROR("Unable to transition to the enclave");
    goto failure;
  }
  return 0;
failure:
  return -1;
}
