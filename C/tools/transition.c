#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>


#define TYCHE_REVOKE_MGMT_ACCESS _IOWR('a', 't', void *)

const char* driver = "/dev/tyche";

int main(void) {
  int fd = open(driver, O_RDWR);
  if (fd < 0) {
    printf("Unable to open the driver.\n");
    exit(1);
  }
  if (ioctl(fd, TYCHE_REVOKE_MGMT_ACCESS, NULL) != 0) {
    printf("Unable to call the driver.\n");
    exit(1);
  }
  printf("Success!\n");
  return 0;
}
