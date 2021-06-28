#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
using namespace std;

#define BUFFER_SIZE 65536

int main(){
    // int fd;
    // mode_t mode = S_IRUSR | S_IWUSR;
    // char pathname[] = "/home/kcwu206/hw2/aaaa";
    // char newname[] = "/home/kcwu206/hw2/bbbb";
    // fd = creat(pathname, mode);
    // mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
    // fd = chmod(pathname, mode);
    // fd = chown(pathname, 65534, 65534);

    // rename(pathname, newname);

    // int fd2;
    // mode_t mode2 = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    // fd2 = open(newname, O_WRONLY | O_CREAT | O_TRUNC, mode2);
    // char buf[] = "My name \n is \n Ayush";
    // size_t nbytes = strlen(buf);
    // write(fd2, buf, nbytes);
    // close(fd2);

    // FILE *f;
    // char *buf;
    // size_t ret;
    // f = fopen("aaa" , "r");
    // buf = (char *)malloc(BUFFER_SIZE);
    // ret = fread(buf, 1, BUFFER_SIZE, f);
    // fclose(f);

    fclose(stderr);

    FILE *fp;
    fp = tmpfile();
    fclose(fp);
    return 0;
}