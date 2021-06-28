#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/stat.h>
#include <errno.h>

int hex_to_dec(char arr[]) {
	int val = 0;
	if(arr[0] <= '9' && arr[0] >= '0') val += (arr[0]-48)*16;
	else val += (arr[0]-87)*16;
	if(arr[1] <= '9' && arr[0] >= '0') val += (arr[1]-48);
	else val += (arr[1]-87);

	return val;
}

int main(int argc, char * argv[]) {
 	int status;
 	pid_t child;
 
 	child = fork();
   	if(child < 0) {
     	perror("fork error");
     	exit(1);
    }
   	else if(child == 0) { //child
     	ptrace(PTRACE_TRACEME, 0, NULL, NULL);
     	execvp(argv[1], argv+1);
     	fprintf(stderr, "execvp error\n");
    }
   	else { //parent
		int fd = open("no_more_traps.txt", O_RDONLY);

		if(waitpid(child, &status, 0) < 0) perror("wait child error!");

     	while(WIFSTOPPED(status)) {
     		int length;
     		char buf[4];
     		long ret;	
			unsigned long long rip;
			struct user_regs_struct regs;
			unsigned char *ptr = (unsigned char*) &ret;
			unsigned char code[8];
			unsigned long *lcode = (unsigned long*) code;
			if((rip = ptrace(PTRACE_PEEKUSER, child, ((unsigned char*) &regs.rip) - ((unsigned char*) &regs), 0)) != 0) {
				ret = ptrace(PTRACE_PEEKTEXT, child, rip, 0);
				if(ptr[0] == 0xcc){
					length = read(fd, buf, 2);
					for(int i=1; i<8; i++){
						code[i] = ptr[i];
					}
					code[0] = hex_to_dec(buf);
					if(ptrace(PTRACE_POKETEXT, child, rip, *lcode) != 0) perror("poke error!");
				}
			}
     		if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) perror("singlestep error!");
     		if(waitpid(child, &status, 0) < 0) perror("wait child error!");
     	}
   	}
    return 0; 
}