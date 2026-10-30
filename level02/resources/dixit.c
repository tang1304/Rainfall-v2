#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char *ptr;

    ptr = getenv(argv[1]);
    if (ptr == NULL) {
        printf("%s not found in environment\n", argv[1]);
        exit(0);
    }
    printf("%s is at %p\n", argv[1], ptr);
    exit(0);
}