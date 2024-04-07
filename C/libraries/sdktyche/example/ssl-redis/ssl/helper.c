#include "help.h"
#include "common.h"
#include "bearssl.h"
#include "config.h"

#include <stddef.h>
#include <sys/types.h>

// —————————————————————————— Debugging functions ——————————————————————————— //
inline void suicide(void) {
  int *suicide = (int *)0xdeadbabe;
  *suicide = 666;
}

void tyche_debug(unsigned long long marker) {
  asm volatile("movq %0, %%rdi\n\t"
               "movq $10, %%rax\n\t"
               "vmcall"
               :
               : "rm"(marker)
               : "rax", "rdi", "memory");
}

// ————————————————————— Replacement for libc functions ————————————————————— //

void *memcpy(void *dest, const void *src, size_t n) {
    char *cdest = dest;
    const char *csrc = src;
    size_t i;
    for (i = 0; i < n; ++i) {
        cdest[i] = csrc[i];
    }
    return dest;
}

size_t strlen(const char *str) {
    const char *ptr = str;
    while (*ptr != '\0') {
        ptr++;
    }
    return ptr - str;
}

void *memmove(void *dest, const void *src, size_t n) {
    char *cdest = dest;
    const char *csrc = src;
    if (cdest < csrc) {
        size_t i;
        for (i = 0; i < n; ++i) {
            cdest[i] = csrc[i];
        }
    } else if (cdest > csrc) {
        size_t i;
        for (i = n; i != 0; --i) {
            cdest[i - 1] = csrc[i - 1];
        }
    }
    return dest;
}

int memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *c1 = s1;
    const unsigned char *c2 = s2;
    size_t i;
    for (i = 0; i < n; ++i) {
        if (c1[i] < c2[i]) return -1;
        else if (c1[i] > c2[i]) return 1;
    }
    return 0;
}

void *memset(void *dest, int value, size_t len) {
    unsigned char *ptr = dest;
    unsigned char byteValue = (unsigned char)value;
    for (size_t i = 0; i < len; ++i) {
        ptr[i] = byteValue;
    }
    return dest;
}

void *__memcpy_chk(void *dest, const void *src, size_t len, size_t dest_size) {
  if (len > dest_size) {
    suicide();
  }
  return memcpy(dest, src, len);
}

void *__memset_chk(void *dest, int value, size_t len, size_t dest_size) {
  if (len > dest_size) {
    suicide();
  }
  return memset(dest, value, len);
}

int *__errno_location(void) {
    // Example implementation (not platform-specific)
    static int errno_value;
    return &errno_value;
}

int open(const char *pathname, int flags) {
  suicide();
  return 0;
}
ssize_t read(int fd, void *buf, size_t count) {
  suicide();
  return 0;
}
int close(int fd) {
  suicide();
  return 0;
}

// Simple xorshift PRNG
static unsigned int xorshift32(unsigned int *state) {
  unsigned int x = *state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  *state = x;
  return x;
}

int getentropy(void *buf, size_t buflen) {
  unsigned char *buffer = (unsigned char *)buf;
  unsigned int state = 123456789; // Initial seed
  size_t i;

  // Generate random bytes
  for (i = 0; i < buflen; i++) {
    buffer[i] = (unsigned char)(xorshift32(&state) % 256);
  }
  return 0;
}
