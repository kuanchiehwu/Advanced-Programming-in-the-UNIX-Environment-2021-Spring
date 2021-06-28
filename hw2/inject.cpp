#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <dlfcn.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
using namespace std;

int chmod(const char *pathname, mode_t mode){
    int re = (* (int (*)(const char *pathname, mode_t mode)) dlsym(RTLD_NEXT, "chmod"))(pathname, mode);
    char resolved_path[PATH_MAX];
    if(realpath(pathname, resolved_path) != NULL){
        fprintf(stderr, "[logger] chmod(\"%s\", %o) = %d\n", resolved_path, mode, re);
    }
    else{
        fprintf(stderr, "[logger] chmod(\"%s\", %o) = %d\n", pathname, mode, re);
    }
    return re;
}

int chown(const char *pathname, uid_t owner, gid_t group){
    int re = (* (int (*)(const char *pathname, uid_t owner, gid_t group)) dlsym(RTLD_NEXT, "chown"))(pathname, owner, group);
    char resolved_path[PATH_MAX];
    if(realpath(pathname, resolved_path) != NULL){
        fprintf(stderr, "[logger] chown(\"%s\", %d, %d) = %d\n", resolved_path, owner, group, re);
    }
    else{
        fprintf(stderr, "[logger] chown(\"%s\", %d, %d) = %d\n", pathname, owner, group, re);
    }
    return re;
}

int close(int fd){
    char path[PATH_MAX], link_dest[PATH_MAX];
    ssize_t link_dest_size;
    sprintf(path, "/proc/%d/fd/%d", getpid(), fd);
    if((link_dest_size = readlink(path, link_dest, sizeof(link_dest)-1)) != -1)
        link_dest[link_dest_size] = '\0';
    // else 
    //     fprintf(stderr, "Fail open %s\n", path);
    int re = (* (int (*)(int fd)) dlsym(RTLD_NEXT, "close"))(fd);
    fprintf(stderr, "[logger] close(\"%s\") = %d\n", link_dest, re);
    return re;
}

int creat(const char *pathname, mode_t mode){
    int re = (* (int (*)(const char *pathname, mode_t mode)) dlsym(RTLD_NEXT, "creat"))(pathname, mode);
    char resolved_path[PATH_MAX];
    if(realpath(pathname, resolved_path) != NULL)
        fprintf(stderr, "[logger] creat(\"%s\", %o) = %d\n", resolved_path, mode, re);
    else
        fprintf(stderr, "[logger] creat(\"%s\", %o) = %d\n", pathname, mode, re);
    return re;
}

int creat64(const char *pathname, mode_t mode){
    int re = (* (int (*)(const char *pathname, mode_t mode)) dlsym(RTLD_NEXT, "creat64"))(pathname, mode);
    char resolved_path[PATH_MAX];
    if(realpath(pathname, resolved_path) != NULL)
        fprintf(stderr, "[logger] creat64(\"%s\", %o) = %d\n", resolved_path, mode, re);
    else
        fprintf(stderr, "[logger] creat64(\"%s\", %o) = %d\n", pathname, mode, re);
    return re;
}

int fclose(FILE *stream){
    int fd = fileno(stream);
    char path[PATH_MAX], link_dest[PATH_MAX];
    ssize_t link_dest_size;
    sprintf(path, "/proc/%d/fd/%d", getpid(), fd);

    if((link_dest_size = readlink(path, link_dest, sizeof(link_dest)-1)) != -1)
        link_dest[link_dest_size] = '\0';
    // else
    //     printf("Fail open %s\n", path);
    
    int re = (* (int (*)(FILE *stream)) dlsym(RTLD_NEXT, "fclose"))(stream);
    fprintf(stderr, "[logger] fclose(\"%s\") = %d\n", link_dest, re);
    return re;
}

FILE *fopen(const char *pathname, const char *mode){
    FILE *re = (* (FILE *(*)(const char *pathname, const char *mode)) dlsym(RTLD_NEXT, "fopen"))(pathname, mode);
    char resolved_path[PATH_MAX];

    if(realpath(pathname, resolved_path) != NULL)
        fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", resolved_path, mode, re);
    else
        fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", pathname, mode, re);
    return re;
}

FILE *fopen64(const char *pathname, const char *mode){
    FILE *re = (* (FILE *(*)(const char *pathname, const char *mode)) dlsym(RTLD_NEXT, "fopen64"))(pathname, mode);
    char resolved_path[PATH_MAX];

    if(realpath(pathname, resolved_path) != NULL)
        fprintf(stderr, "[logger] fopen64(\"%s\", \"%s\") = %p\n", resolved_path, mode, re);
    else
        fprintf(stderr, "[logger] fopen64(\"%s\", \"%s\") = %p\n", pathname, mode, re);
    return re;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream){
    size_t re = (* (size_t (*)(void *ptr, size_t size, size_t nmemb, FILE *stream)) dlsym(RTLD_NEXT, "fread"))(ptr, size, nmemb, stream);
    
    char *temp = (char *)ptr;
    char buffer[32];
    int len = strlen(temp);
    if(len > 32) len = 32;
    for(int i=0; i<len; i++){
        if(!isprint(temp[i]))
            buffer[i] = '.';
        else
            buffer[i] = temp[i];
    }
    buffer[len] = '\0';

    char path[PATH_MAX], link_dest[PATH_MAX];
    ssize_t link_dest_size;
    int fd = fileno(stream);
    sprintf(path, "/proc/%d/fd/%d", getpid(), fd);

    if((link_dest_size = readlink(path, link_dest, sizeof(link_dest)-1)) != 1)
        link_dest[link_dest_size] = '\0';

    fprintf(stderr, "[logger] fread(\"%s\", %d, %d, \"%s\") = %d\n", buffer, size, nmemb, link_dest, re);
    return re;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream){
    size_t re = (* (size_t (*)(const void *ptr, size_t size, size_t nmemb, FILE *stream)) dlsym(RTLD_NEXT, "fwrite"))(ptr, size, nmemb, stream);
    
    char *temp = (char *)ptr;
    char buffer[32];
    int len = strlen(temp);
    if(len > 32) len = 32;
    for(int i=0; i<len; i++){
        if(!isprint(temp[i]))
            buffer[i] = '.';
        else
            buffer[i] = temp[i];
    }
    buffer[len] = '\0';

    char path[PATH_MAX], link_dest[PATH_MAX];
    ssize_t link_dest_size;
    int fd = fileno(stream);
    sprintf(path, "/proc/%d/fd/%d", getpid(), fd);

    if((link_dest_size = readlink(path, link_dest, sizeof(link_dest)-1)) != 1)
        link_dest[link_dest_size] = '\0';

    fprintf(stderr, "[logger] fwrite(\"%s\", %d, %d, \"%s\") = %d\n", buffer, size, nmemb, link_dest, re);
    return re;
}

int open(const char *pathname, int flags, ...){
    int re = -1;
    char resolved_path[PATH_MAX];
    va_list args;
    va_start(args, flags);
    mode_t mode = va_arg(args, mode_t);

    if(mode > 0777 | mode < 0){
        re = (* (int (*)(const char *pathname, int flags, ...)) dlsym(RTLD_NEXT, "open"))(pathname, flags);
        if(realpath(pathname, resolved_path) != NULL)
            fprintf(stderr, "[logger] open(\"%s\", %o, 0) = %d\n", resolved_path, flags, re);
        else
            fprintf(stderr, "[logger] open(\"%s\", %o, 0) = %d\n", pathname, flags, re);
    }
    else{
        re = (* (int (*)(const char *pathname, int flags, ...)) dlsym(RTLD_NEXT, "open"))(pathname, flags, mode);
        if(realpath(pathname, resolved_path) != NULL)
            fprintf(stderr, "[logger] open(\"%s\", %o, %o) = %d\n", resolved_path, flags, mode, re);
        else
            fprintf(stderr, "[logger] open(\"%s\", %o, %o) = %d\n", pathname, flags, mode, re);
    }
    return re;
}

int open64(const char *pathname, int flags, ...){
    int re = -1;
    char resolved_path[PATH_MAX];
    va_list args;
    va_start(args, flags);
    mode_t mode = va_arg(args, mode_t);

    if(mode > 0777 | mode < 0){
        re = (* (int (*)(const char *pathname, int flags, ...)) dlsym(RTLD_NEXT, "open64"))(pathname, flags);
        if(realpath(pathname, resolved_path) != NULL)
            fprintf(stderr, "[logger] open64(\"%s\", %o, 0) = %d\n", resolved_path, flags, re);
        else
            fprintf(stderr, "[logger] open64(\"%s\", %o, 0) = %d\n", pathname, flags, re);
    }
    else{
        re = (* (int (*)(const char *pathname, int flags, ...)) dlsym(RTLD_NEXT, "open64"))(pathname, flags, mode);
        if(realpath(pathname, resolved_path) != NULL)
            fprintf(stderr, "[logger] open64(\"%s\", %o, %o) = %d\n", resolved_path, flags, mode, re);
        else
            fprintf(stderr, "[logger] open64(\"%s\", %o, %o) = %d\n", pathname, flags, mode, re);
    }
    return re;
}

ssize_t read(int fd, void *buf, size_t count){
    ssize_t re = (* (size_t (*)(int fd, void *buf, size_t count)) dlsym(RTLD_NEXT, "read"))(fd, buf, count);
    
    char path[PATH_MAX], link_dest[PATH_MAX];
    ssize_t link_dest_size;
    sprintf(path, "/proc/%d/fd/%d", getpid(), fd);

    if((link_dest_size = readlink(path, link_dest, sizeof(link_dest)-1)) != -1)
        link_dest[link_dest_size] = '\0';

    char *temp = (char *)buf;
    char buffer[32];
    int len = strlen(temp);
    if(len > 32) len = 32;
    for(int i=0; i<len; i++){
        if(!isprint(temp[i]))
            buffer[i] = '.';
        else
            buffer[i] = temp[i];
    }
    buffer[len] = '\0';

    fprintf(stderr, "[logger] read(\"%s\", \"%s\", %d) = %d\n", link_dest, buffer, count, re);
    return re;
}

int remove(const char *pathname){
    int re = (* (int (*)(const char *pathname)) dlsym(RTLD_NEXT, "remove"))(pathname);
    char resolved_path[PATH_MAX];

    if(realpath(pathname, resolved_path) != NULL)
        fprintf(stderr, "[logger] remove(\"%s\") = %d\n", resolved_path, re);
    else
        fprintf(stderr, "[logger] remove(\"%s\") = %d\n", pathname, re);
    return re;
}

int rename(const char *oldname, const char *newname){
    int re = (* (int (*)(const char *oldname, const char *newname)) dlsym(RTLD_NEXT, "rename"))(oldname, newname);
    char old_resolved_path[PATH_MAX], new_resolved_path[PATH_MAX];
    if(realpath(oldname, old_resolved_path) != NULL){
        if(realpath(newname, new_resolved_path) != NULL)
            fprintf(stderr, "[logger] rename(\"%s\", \"%s\") = %d\n", old_resolved_path, new_resolved_path, re);
        else
            fprintf(stderr, "[logger] rename(\"%s\", \"%s\") = %d\n", old_resolved_path, newname, re);
    }
    else{
        if(realpath(newname, new_resolved_path) != NULL)
            fprintf(stderr, "[logger] rename(\"%s\", \"%s\") = %d\n", oldname, new_resolved_path, re);
        else
            fprintf(stderr, "[logger] rename(\"%s\", \"%s\") = %d\n", oldname, newname, re);
    }
    return re;
}

FILE *tmpfile(void){
    FILE *re = (* (FILE *(*)(void)) dlsym(RTLD_NEXT, "tmpfile"))();
    fprintf(stderr, "[logger] tmpfile() = %p\n", re);
    return re;
}

FILE *tmpfile64(void){
    FILE *re = (* (FILE *(*)(void)) dlsym(RTLD_NEXT, "tmpfile64"))();
    fprintf(stderr, "[logger] tmpfile64() = %p\n", re);
    return re;
}

ssize_t write(int fd, const void *buf, size_t count){
    ssize_t re = (* (ssize_t (*)(int fd, const void *buf, size_t count)) dlsym(RTLD_NEXT, "write"))(fd, buf, count);
    
    char path[PATH_MAX], link_dest[PATH_MAX];
    ssize_t link_dest_size;
    sprintf(path, "/proc/%d/fd/%d", getpid(), fd);

    if((link_dest_size = readlink(path, link_dest, sizeof(link_dest)-1)) != -1)
        link_dest[link_dest_size] = '\0';

    char *temp = (char *)buf;
    char buffer[32];
    int len = strlen(temp);
    if(len > 32) len = 32;
    for(int i=0; i<len; i++){
        if(!isprint(temp[i]))
            buffer[i] = '.';
        else
            buffer[i] = temp[i];
    }
    buffer[len] = '\0';
    
    fprintf(stderr, "[logger] write(\"%s\", \"%s\", %d) = %d\n", link_dest, buffer, count, re);
    return re;
}
