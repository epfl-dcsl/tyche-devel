#define _GNU_SOURCE
#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int futex(int *uaddr, int futex_op, int val, const struct timespec *timeout, int val2) {
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, NULL, val2);
}

static void my_little_test() {
  int* uaddr = (int*) mmap((void*) 0x70000, 0x1000, PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
  if (uaddr == MAP_FAILED) {
    perror("Failed in the mmap");
    abort();
  }
  int ret = futex(uaddr, FUTEX_WAIT_BITSET, 0, NULL, FUTEX_BITSET_MATCH_ANY);
  if (ret == -1) {
    perror("Futex failed");
    abort();
  }
  printf("We are done!");
}


static void test_futex(void) {
    int contalloc = open("/dev/contalloc", O_RDWR);
    if (contalloc < 0) {
      perror("Failed to open driver");
      abort();
    }

    // The address you provided (assuming it's valid in your context)
    int *uaddr = (int*) mmap((void*) 0x70000, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED_NOREPLACE, contalloc, 0);
    if (uaddr == MAP_FAILED) {
      perror("mmap failed");
      abort();
    }
    if (uaddr != (int*) 0x70000) {
      perror("failed to get the desired address");
      abort();
    }

    // Perform the futex call
    int ret = futex(uaddr, FUTEX_WAIT_BITSET, 0, NULL, FUTEX_BITSET_MATCH_ANY);
    if (ret == -1) {
        perror("futex failed");
        abort();
    }

    printf("Futex call returned: %d\n", ret);
    close(contalloc);
}

typedef struct msg_info_t {
  unsigned long long virt;
  unsigned long long phys;
  unsigned long long size;
} msg_info_t;

static void test_mmap(void) {
  void* addr = mmap(NULL, 22 * 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE
      | MAP_LOCKED,
      -1, 0);
  if (addr == MAP_FAILED) {
    perror("Unable to do the mmaping.");
    abort();
  }

  msg_info_t msg = {(unsigned long long) addr, 0, 22 * 0x1000};
  int fd = open("/dev/contalloc", O_RDWR);
  if (ioctl(fd, 0x555, &msg) != 0) {
    perror("Problemo");
    abort();
  }
  printf("Apparently everything worked with addr %p\n", addr);
}

int main() {
  my_little_test();
  //test_mmap();
  //test_futex();
  return 0;
}
