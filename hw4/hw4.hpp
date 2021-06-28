#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <fstream>
#include <sstream>
#include <capstone/capstone.h>
#include <elf.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <errno.h>
using namespace std;

#define PATH_MAX 4096
#define BP_MAX 20

typedef struct bp{
    int used;
    unsigned long long addr;
    unsigned long long ori;
} bp_t;

typedef struct SDB{
    csh cshandle;
    char path[PATH_MAX];
    pid_t pid;
    bp breakpoints[BP_MAX];
    unsigned long long base_addr;
    unsigned long long end_addr;
} SDB;

char help_msg[] = "- break {instruction-address}: add a break point\n"
                  "- cont: continue execution\n"
                  "- delete {break-point-id}: remove a break point\n"
                  "- disasm addr: disassemble instructions in a file or a memory region\n"
                  "- dump addr [length]: dump memory content\n"
                  "- exit: terminate the debugger\n"
                  "- get reg: get a single value from a register\n"
                  "- getregs: show registers\n"
                  "- help: show this message\n"
                  "- list: list break points\n"
                  "- load {path/to/a/program}: load a program\n"
                  "- run: run the program\n"
                  "- vmmap: show memory layout\n"
                  "- set reg val: get a single value to a register\n"
                  "- si: step into instruction\n"
                  "- start: start the program and stop at the first instruction\n";

SDB *sdb_create(){
    SDB *sdb = (SDB*)malloc(sizeof(SDB));
    cs_open(CS_ARCH_X86, CS_MODE_64, &(sdb->cshandle));
    sdb->path[0] = '\0';
    sdb->pid = -1;
    for(int i=0; i<BP_MAX; i++)
        sdb->breakpoints[i].used = 0;
    sdb->base_addr = 0;
    sdb->end_addr = 0;
    return sdb;
}

bool check_load(SDB *sdb){
    if(strcmp(sdb->path, "") == 0) return 0;
    else return 1;
}

bool check_run(SDB *sdb){
    if(!check_load(sdb)){
        printf("** No program loaded.\n");
        return 0;
    }
    else if(sdb->pid == -1) return 0;
    else return 1;
}

unsigned long long str_to_ull(const string &s){
    if(s.find("0x") == 0 || s.find("0X") == 0)
        return stoull(s, NULL, 16);
    else if(s.find("0") == 0)
        return stoull(s, NULL, 8);
    else
        return stoull(s);
}

void patch_bp(SDB *sdb){
    for(int i=0; i<BP_MAX; i++){
        bp_t *bp = &(sdb->breakpoints[i]);
        if(bp->used){
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, sdb->pid, 0, &regs);
            if(regs.rip == bp->addr){
                ptrace(PTRACE_SINGLESTEP, sdb->pid, 0, 0);
                if(waitpid(sdb->pid, 0, 0) < 0)
                    printf("** wait fail\n");
            }
            
            unsigned long long word = ptrace(PTRACE_PEEKTEXT, sdb->pid, bp->addr, 0);
            if ((word & 0xff) == 0xcc)
				continue;
			bp->ori = word;

            if(ptrace(PTRACE_POKETEXT, sdb->pid, bp->addr, (bp->ori & 0xffffffffffffff00) | 0xcc) != 0) {
				printf("** patch_bp fail\n");
				return;
			}
        }
    }
}

void sdb_help(){
    printf("%s", help_msg);
}

void sdb_load(SDB *sdb, char *filename){
    if(check_load(sdb)){
        printf("** Program %s already loaded.\n", sdb->path);
        return;
    }
    FILE *f;
    Elf64_Ehdr elf_head;
    f = fopen(filename, "r");
    fread(&elf_head, sizeof(Elf64_Ehdr), 1, f);
    printf("** program '%s' loaded. entry point 0x%lx\n", filename, elf_head.e_entry);

    strcpy(sdb->path, filename);
    sdb->pid = -1;
    for(int i=0; i<BP_MAX; i++)
        sdb->breakpoints[i].used = 0;
    sdb->base_addr = 0;
    sdb->end_addr = 0;
}

void sdb_start(SDB *sdb){
    if(check_load(sdb) == 0){
        printf("** Program is not loaded. Try \"load\" to load the program.\n");
        return;
    }

    int wstatus;
    if((sdb->pid = fork()) < 0){
        printf("** fork fail");
        return;
    }
    if(sdb->pid == 0){
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0){
            printf("** ptrace fail");
            exit(-1);
        }
        execlp(sdb->path, sdb->path, NULL);
        perror("** execlp");
        exit(-1);
    }
    else{
        if(waitpid(sdb->pid, &wstatus, 0) < 0){
            printf("** waitpid fail");
            return;
        }
        ptrace(PTRACE_SETOPTIONS, sdb->pid, 0, PTRACE_O_EXITKILL);
        printf("** pid %d\n", sdb->pid);

        // get base addr
        ifstream f("/proc/" + to_string(sdb->pid) + "/stat");
        string s, t;
        vector<string> v;
        getline(f, s);
        istringstream in(s);
        while(in >> t)
            v.push_back(t);
        sdb->base_addr = str_to_ull(v[25]);
        sdb->end_addr = str_to_ull(v[26]);

        // set breakpoints
        patch_bp(sdb);
    }
}

void sdb_exit(SDB *sdb){
    printf("Bye.\n");
    if(sdb->pid != -1)
        kill(sdb->pid, SIGTERM);
}

void sdb_break(SDB *sdb, char *addr){
    if(!check_run(sdb)){
        printf("** Program is loaded but not run\n");
        return;
    }

    bp_t *bp;
    for(int i=0; i<BP_MAX; i++){
        if(!sdb->breakpoints[i].used){
            bp = &(sdb->breakpoints[i]);
            break;
        }
    }
    bp->used = 1;
    bp->addr = str_to_ull(addr);
    
    // if run set breakpoints
    if(check_run(sdb))
        patch_bp(sdb);
}

void sdb_list(SDB *sdb){
    for(int i=0; i<BP_MAX; i++){
        bp_t *bp = &(sdb->breakpoints[i]);
        if(bp->used)
            printf("%3d:  %llx\n", i, bp->addr);
    }
}

void sdb_cont(SDB *sdb){
    if(!check_run(sdb)){
        printf("** Program is not run.\n");
        return;
    }

    patch_bp(sdb);

    int status;
    ptrace(PTRACE_CONT, sdb->pid, 0, 0);
    while(waitpid(sdb->pid, &status, 0) > 0){
        if(!WIFSTOPPED(status)) continue;

        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, sdb->pid, 0, &regs);

        for(int i=0; i<BP_MAX; i++){
            bp_t *bp = &(sdb->breakpoints[i]);
            if(bp->used && bp->addr == (regs.rip - 1)){
                ptrace(PTRACE_POKETEXT, sdb->pid, bp->addr, bp->ori);
                regs.rip--;
                ptrace(PTRACE_SETREGS, sdb->pid, 0, &regs);

                unsigned long long buf;
                buf = ptrace(PTRACE_PEEKTEXT, sdb->pid, bp->addr, 0);
                cs_insn *insn;
                size_t count;
                if((count = cs_disasm(sdb->cshandle, (uint8_t*)&buf, 8, bp->addr, 0, &insn)) > 0){
                    char bytes_str[16] = "";
                    char byte[8];
                    for(int j = 0; j < insn[0].size; ++j) {
						sprintf(byte, "%02x ", insn[0].bytes[j]);
						strcat(bytes_str, byte);
					}
                    
                    printf("** breakpoint @ %10lx: %-21s", insn[0].address, bytes_str);
					printf("%-10s%s\n", insn[0].mnemonic, insn[i].op_str);
					cs_free(insn, count);
                }
                else
                    printf("cont fail\n");

                return;
            }
        }
    }
    if(status == 0)
        printf("** child process %d terminiated normally (code 0)\n", sdb->pid);
    else
        printf("** child process %d terminiated abnormally (code %d)\n", sdb->pid, status);
    sdb->pid = -1;
}

void sdb_run(SDB *sdb){
    if(check_run(sdb)){
        printf("** program %s is already running.\n", sdb->path);
        sdb_cont(sdb);
    }
    else if(check_load(sdb)){
        sdb_start(sdb);
        sdb_cont(sdb);
    }
    else
        printf("** No program is loaded.\n");
}

void sdb_delete(SDB *sdb, int num){
    if(!check_run(sdb)){
        printf("** Program is not run.\n");
        return;
    }

    if(num >= 0 && num < BP_MAX && sdb->breakpoints[num].used){
        bp_t *bp = &(sdb->breakpoints[num]);
        unsigned long long word = ptrace(PTRACE_PEEKTEXT, sdb->pid, bp->addr, 0);
        if ((word & 0xff) == 0xcc) {
			ptrace(PTRACE_POKETEXT, sdb->pid, bp->addr, bp->ori);
		}

        bp->used = 0;
        printf("** breakpoint %d deleted.\n", num);
    }
}

void sdb_si(SDB *sdb){
    if(!check_run(sdb)){
        printf("** Program is not run.\n");
        return;
    }
    if(ptrace(PTRACE_SINGLESTEP, sdb->pid, 0,0) < 0) {
		printf("** si failed\n");
		return;
	}
	if(waitpid(sdb->pid, 0, 0) < 0)
        printf("wait fail\n");
}

void sdb_getregs(SDB *sdb){
    if(!check_run(sdb)){
        printf("** Program is not run.\n");
        return;
    }

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, sdb->pid, 0, &regs);
    printf("RAX %-16llx RBX %-16llx RCX %-16llx RDX %-16llx\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
    printf("R8  %-16llx R9  %-16llx R10 %-16llx R11 %-16llx\n", regs.r8, regs.r9, regs.r10, regs.r11);
    printf("R12 %-16llx R13 %-16llx R14 %-16llx R15 %-16llx\n", regs.r12, regs.r13, regs.r14, regs.r15);
    printf("RDI %-16llx RSI %-16llx RBP %-16llx RSP %-16llx\n", regs.rdi, regs.rsi, regs.rbp, regs.rsp);
    printf("RIP %-16llx FLAGS %016llx\n", regs.rip, regs.eflags);
}

void sdb_get(SDB *sdb, char *reg){
    if(!check_run(sdb)){
        printf("** Program is not run.\n");
        return;
    }

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, sdb->pid, 0, &regs);

    unsigned long long val;

    if(strcmp(reg, "rax") == 0) val = regs.rax;
    else if(strcmp(reg, "rbx") == 0) val = regs.rbx;
    else if(strcmp(reg, "rcx") == 0) val = regs.rcx;
    else if(strcmp(reg, "rdx") == 0) val = regs.rdx;
    else if(strcmp(reg, "r8") == 0) val = regs.r8;
    else if(strcmp(reg, "r9") == 0) val = regs.r9;
    else if(strcmp(reg, "r10") == 0) val = regs.r10;
    else if(strcmp(reg, "r11") == 0) val = regs.r11;
    else if(strcmp(reg, "r12") == 0) val = regs.r12;
    else if(strcmp(reg, "r13") == 0) val = regs.r13;
    else if(strcmp(reg, "r14") == 0) val = regs.r14;
    else if(strcmp(reg, "r15") == 0) val = regs.r15;
    else if(strcmp(reg, "rdi") == 0) val = regs.rdi;
    else if(strcmp(reg, "rsi") == 0) val = regs.rsi;
    else if(strcmp(reg, "rbp") == 0) val = regs.rbp;
    else if(strcmp(reg, "rsp") == 0) val = regs.rsp;
    else if(strcmp(reg, "rip") == 0) val = regs.rip;
    else if(strcmp(reg, "eflags") == 0) val = regs.eflags;
    else{
        printf("** no such register\n");
        return;
    }
    printf("%s = %llu (0x%llx)\n", reg, val, val);
}

void sdb_vmmap(SDB *sdb){
    if(!check_run(sdb)){
        printf("** Program is not run.\n");
        return;
    }
    
    ifstream f("/proc/" + to_string(sdb->pid) + "/maps");
    string s, t;
    while(getline(f, s)){
        vector<string> v;
        istringstream in(s);
        while(in >> t){
            v.push_back(t);
            // cout << t << endl;
        }
        stringstream a(v[0]);
        vector<string> addr;
        char delim = '-';
        string temp;
        while(getline(a, temp, delim)){
            addr.push_back(temp);
        }
        cout << setw(16) << setfill('0') << addr[0] << "-" << setw(16) << setfill('0') << addr[1];
        printf(" %s %-8s %s\n", v[1].c_str(), v[4].c_str(), v[5].c_str());
    }
    f.close();
}

void sdb_set(SDB *sdb, char *reg, unsigned long long val){
    if(!check_run(sdb)){
        printf("** Program is not run.\n");
        return;
    }

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, sdb->pid, 0, &regs);

    if(strcmp(reg, "rax") == 0) regs.rax = val;
    else if(strcmp(reg, "rbx") == 0) regs.rbx = val;
    else if(strcmp(reg, "rcx") == 0) regs.rcx = val;
    else if(strcmp(reg, "rdx") == 0) regs.rdx = val;
    else if(strcmp(reg, "r8") == 0) regs.r8 = val;
    else if(strcmp(reg, "r9") == 0) regs.r9 = val;
    else if(strcmp(reg, "r10") == 0) regs.r10 = val;
    else if(strcmp(reg, "r11") == 0) regs.r11 = val;
    else if(strcmp(reg, "r12") == 0) regs.r12 = val;
    else if(strcmp(reg, "r13") == 0) regs.r13 = val;
    else if(strcmp(reg, "r14") == 0) regs.r14 = val;
    else if(strcmp(reg, "r15") == 0) regs.r15 = val;
    else if(strcmp(reg, "rdi") == 0) regs.rdi = val;
    else if(strcmp(reg, "rsi") == 0) regs.rsi = val;
    else if(strcmp(reg, "rbp") == 0) regs.rbp = val;
    else if(strcmp(reg, "rsp") == 0) regs.rsp = val;
    else if(strcmp(reg, "rip") == 0) regs.rip = val;
    else if(strcmp(reg, "eflags") == 0) regs.eflags = val;
    else{
        printf("** no such register\n");
        return;
    }

    if(ptrace(PTRACE_SETREGS, sdb->pid, 0, &regs) != 0) {
		printf("** set regs fail\n");
		return;
	}
}

void sdb_dump(SDB *sdb, char *addr_s){
    if(!check_run(sdb)){
        printf("** Program is not run.\n");
        return;
    }

    if(strcmp(addr_s, "") == 0){
        printf("** no addr given.\n");
        return;
    }

    unsigned long long addr = str_to_ull(addr_s);
    
    if(addr > sdb->end_addr){
        return;
    }

    unsigned char buf[80];
    for(unsigned long long ptr=addr; ptr<(addr+sizeof(buf)); ptr+=8){
        errno = 0;
        unsigned long long t = ptrace(PTRACE_PEEKTEXT, sdb->pid, ptr, NULL);
        if(errno != 0) break;

        memcpy(&buf[ptr - addr], &t, 8);
    }

    for(int i=0; i<5; i++){
        printf("%12llx:", addr + (i * 16));
        for(int j=0; j<16; j++){
            unsigned char word = buf[i * 16 + j];
            printf(" %02x", word);
        }
        printf("  |");
        for(int j=0; j<16; j++){
            char tmp = buf[i * 16 + j];
            if(isprint(tmp))
                printf("%c", tmp);
            else
                printf(".");
        }
        printf("|\n");
    }
}

void sdb_disasm(SDB *sdb, char *addr_s){
    if(!check_run(sdb)){
        printf("** Program is not run.\n");
        return;
    }

    if(strcmp(addr_s, "") == 0){
        printf("** no addr given.\n");
        return;
    }

    unsigned long long addr = str_to_ull(addr_s);

    // if((addr < sdb->base_addr) | (addr > sdb->end_addr)){
    //     printf("** out of range\n");
    //     return;
    // }

    for(int i=0; i<BP_MAX; i++){
        bp_t *bp = &(sdb->breakpoints[i]);
        if(bp->used){
            if(ptrace(PTRACE_POKETEXT, sdb->pid, bp->addr, bp->ori) != 0)
					printf("** patch fail\n");
        }
    }

    unsigned long long ptr;
    char buf[64] = {0};
    for(ptr=addr; ptr < addr + sizeof(buf); ptr+=8){
        errno = 0;
        unsigned long long t = ptrace(PTRACE_PEEKTEXT, sdb->pid, ptr, NULL);
        if(errno != 0) break;

        memcpy(&buf[ptr - addr], &t, 8);
    }
    
    patch_bp(sdb);

    cs_insn *insn;
	size_t count;
	if((count = cs_disasm(sdb->cshandle, (uint8_t*)buf, ptr-addr, addr, 0, &insn)) > 0){
        for(unsigned int i=0; i<count && i<10; i++){
            char byte[16] = "";
            char tmp[8];
            for(int j=0; j<insn[i].size; j++){
                sprintf(tmp, "%02x ", insn[i].bytes[j]);
                strcat(byte, tmp);
            }

            printf("%12lx: %-30s %-6s %s\n", insn[i].address, byte, insn[i].mnemonic, insn[i].op_str);
        }
        cs_free(insn, count);
    }
    else
        printf("** disassemble fail\n");
}