#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

const char *str = "Arbitrary string to be written to a file.\n";

int main(void)
{
    const char *filename = "innn";

    int fd = open(filename, O_RDWR | O_CREAT);
    if (fd == -1)
    {
        perror("open");
        exit(EXIT_FAILURE);
    }

    write(fd, str, strlen(str));
    printf("Done Writing!\n");

    close(fd);

    exit(EXIT_SUCCESS);
}
