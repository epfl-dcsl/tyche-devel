#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

static const char* driver = "/dev/contalloc";
static unsigned long long mmap_size = 0x1000;
static int nb_alloc = 10;

int main(void) {
	void *allocs[nb_alloc];
	int fd = open(driver, O_RDWR);
	if (fd < 0) {
		printf("Unable to open the driver\n");
		exit(-1);
	}
	for (int i = 0; i < nb_alloc; i++) {
		allocs[i] =  mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (allocs[i] == MAP_FAILED) {
			printf("failed the mmap\n");
			exit(-1);
		}
		printf("Mapped %d\n", i);
	}
	printf("All allocations worked.\n");
	for (int i = 0; i < nb_alloc; i++) {
		munmap(allocs[i], mmap_size);
	}
	printf("Survived unmap\n");
	close(fd);
	printf("Survived closed\n");
	return 0;
}
