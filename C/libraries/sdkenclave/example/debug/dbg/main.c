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
  int driver_fd = -1;
  enclave_handle_t handle = -1;
  size_t size = 5 * PAGE_SIZE;
  usize virt_addr = 0;
  usize phys_addr = 0;
  size_t my_func_size = 35; // in bytes
  // I computed the indices by hand.
  usize dest_addr = 0x400000;
  size_t lvl4 = 0, lvl3 = 0, lvl2 = 2, lvl1 = 0;
  usize flags = PT_PP | PT_RW | PT_ACC | PT_DIRT;
  driver_fd = open("/dev/tyche", O_RDWR);
  if (driver_fd < 0) {
    ERROR("Unable to open the driver");
    goto failure;
  }

  if (ioctl_create_enclave(driver_fd, &handle) != SUCCESS) {
    ERROR("Unable to create an enclave");
    goto failure;
  }
  
  if (ioctl_mmap(driver_fd, handle, size, &virt_addr) != SUCCESS) {
    ERROR("Unable to mmap!");
    goto failure;
  } 

  // Zero-out everything.
  memset((void*) virt_addr, 0, size);

  if (ioctl_getphysoffset_enclave(
        driver_fd, handle, virt_addr, &phys_addr) != SUCCESS) {
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

  /*
  do {
    usize physaddr = 0;
    LOG("About to walk for %llx", (usize) attempt);
    // Make sure it's populated.
    attempt[0] = 'a';
    if (attempt[0] != 'a') {
      ERROR("What the hell");
      goto failure;
    }
    if (ioctl_debug_addr(driver_fd, (usize) attempt, &physaddr) != SUCCESS) {
      ERROR("Failed with the attempt data too.");
      goto failure;
    }
    LOG("We found it %llx -> %llx", (usize) attempt, physaddr);
  } while(0);

    // Let's checkout the mappings now.
  for (usize vaddr = virt_addr; vaddr < virt_addr + size; vaddr += PAGE_SIZE) {
    usize physaddr = 0;
    if (ioctl_debug_addr(driver_fd, vaddr, &physaddr) != SUCCESS) {
      ERROR("Unable to get the debugged phys address for %llx", vaddr);
      goto failure;
    }
    LOG("DBG: vaddr: %llx, paddr: %llx", vaddr, physaddr);
  }*/

  // Do the mprotect.
  if (ioctl_mprotect_enclave(
        driver_fd,
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
        driver_fd,
        handle,
        phys_addr + PAGE_SIZE,
        dest_addr,
        0x6000) != SUCCESS) {
    ERROR("Unable to commit the enclave.");
    goto failure;
  }
  LOG("Done creating the enclave.");

  // Call the enclave.
  if (ioctl_switch_enclave(driver_fd, handle, NULL) != SUCCESS) {
    ERROR("Unable to transition to the enclave");
    goto failure;
  }
  return 0;
failure:
  return -1;
}
