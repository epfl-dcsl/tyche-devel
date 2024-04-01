#include <stdio.h>

int main(int argc, char *argv[], char *envp[]) {
    int i;

    printf("Command-line arguments:\n");
    for (i = 0; i < argc; i++) {
        printf("argv[%d]: %s\n", i, argv[i]);
    }

    printf("\nEnvironment variables:\n");
    for (i = 0; envp[i] != NULL; i++) {
        printf("%s\n", envp[i]);
    }

    return 0;
}
