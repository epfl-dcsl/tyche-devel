#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>

typedef void (*maker) (int*);

int main(void) {
  int a = 30;
  make_one(&a);
  if (a != 1) {
    printf("Did not work\n");
    goto failure;
  } else {
    printf("It did work\n");
  }
  // Now try to mmap that shit.
  void* dest = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
  if (dest == MAP_FAILED) {
    printf("Couldn't mmap\n");
    goto failure;
  }
  memcpy(dest, make_one, 13);
  a = 35;
  maker copied_func = (maker) dest;
  copied_func(&a);
  if (a == 1) {
    printf("It worked again!\n");
  } else {
    printf("It failed the second time!\n");
  }
  return 0;
failure:
  return -1;
}
