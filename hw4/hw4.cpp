#include "hw4.hpp"

bool break_while = false;

void start_pro(SDB *sdb, string s, char cmd[64]){
    if(strcmp(cmd, "break") == 0 || strcmp(cmd, "b") == 0){
        char addr[20];
        sscanf(s.c_str(), "%s %s", cmd, addr);
        sdb_break(sdb, addr);
    }
    else if(strcmp(cmd, "cont") == 0 || strcmp(cmd, "c") == 0){
        sdb_cont(sdb);
    }
    else if(strcmp(cmd, "delete") == 0){
        int n_bp;
        sscanf(s.c_str(), "%s %d", cmd, &n_bp);
        sdb_delete(sdb, n_bp);
    }
    else if(strcmp(cmd, "disasm") == 0 || strcmp(cmd, "d") == 0){
        char addr[20];
        addr[0] = '\0';
        sscanf(s.c_str(), "%s %s", cmd, addr);
        sdb_disasm(sdb, addr);
    }
    else if(strcmp(cmd, "dump") == 0 || strcmp(cmd, "x") == 0){
        char addr[20];
        addr[0] = '\0';
        sscanf(s.c_str(), "%s %s", cmd, addr);
        sdb_dump(sdb, addr);
    }
    else if(strcmp(cmd, "exit") == 0 || strcmp(cmd, "q") == 0){
        sdb_exit(sdb);
        break_while = true;
    }
    else if(strcmp(cmd, "get") == 0 || strcmp(cmd, "g") == 0){
        char reg[16];
        sscanf(s.c_str(), "%s %s", cmd, reg);
        sdb_get(sdb, reg);
    }
    else if(strcmp(cmd, "getregs") == 0){
        sdb_getregs(sdb);
    }
    else if(strcmp(cmd, "help") == 0 || strcmp(cmd, "h") == 0){
        sdb_help();
    }
    else if(strcmp(cmd, "list") == 0 || strcmp(cmd, "l") == 0){
        sdb_list(sdb);
    }
    else if(strcmp(cmd, "load") == 0){
        char filename[64];
        sscanf(s.c_str(), "%s %s", cmd, filename);
        sdb_load(sdb, filename);
    }
    else if(strcmp(cmd, "run") == 0 || strcmp(cmd, "r") == 0){
        sdb_run(sdb);
    }
    else if(strcmp(cmd, "vmmap") == 0 || strcmp(cmd, "m") == 0){
        sdb_vmmap(sdb);
    }
    else if(strcmp(cmd, "set") == 0 || strcmp(cmd, "s") == 0){
        char reg[16], val_c[20];
        sscanf(s.c_str(), "%s %s %s", cmd, reg, val_c);
        sdb_set(sdb, reg, str_to_ull(val_c));
    }
    else if(strcmp(cmd, "si") == 0){
        sdb_si(sdb);
    }
    else if(strcmp(cmd, "start") == 0){
        sdb_start(sdb);
    }
    else{
        printf("Undefined command: \"%s\".  Try \"help\".\n", cmd);
    }
}

int main(int argc, char *argv[]){
    string s;
    char cmd[64];
    SDB *sdb = sdb_create();

    if(argc == 2) sdb_load(sdb, argv[1]);
    // if((argc >= 2) && (strcmp(argv[1], "-s") != 0)) sdb_load(sdb, argv[1])
    
    else if((argc >= 2) && (strcmp(argv[1], "-s") == 0)){
        FILE *f;
        f = fopen(argv[2], "r");

        char line[200];
        
        fgets(line, 100, f);
        strtok(line, "\n");
        s = line;
        sscanf(s.c_str(), "%s", cmd);
        if(strcmp(cmd, "load") != 0){
            sdb_load(sdb, argv[3]);
        }
        fseek(f, 0, SEEK_SET);

        while(!feof(f)){
            fgets(line, 100, f);
            strtok(line, "\n");
            s = line;
            sscanf(s.c_str(), "%s", cmd);
            start_pro(sdb, s, cmd);
            // cout << s << endl;
        }
        sdb_exit(sdb);
        fclose(f);

        return 0;
    }
    
    
    while(1){
        printf("sdb> ");
        getline(cin, s);
        sscanf(s.c_str(), "%s", cmd);
        
        start_pro(sdb, s, cmd);

        if(break_while) break;
        // if(strcmp(cmd, "break") == 0 || strcmp(cmd, "b") == 0){
        //     char addr[20];
        //     sscanf(s.c_str(), "%s %s", cmd, addr);
        //     sdb_break(sdb, addr);
        // }
        // else if(strcmp(cmd, "cont") == 0 || strcmp(cmd, "c") == 0){
        //     sdb_cont(sdb);
        // }
        // else if(strcmp(cmd, "delete") == 0){
        //     int n_bp;
        //     sscanf(s.c_str(), "%s %d", cmd, &n_bp);
        //     sdb_delete(sdb, n_bp);
        // }
        // else if(strcmp(cmd, "disasm") == 0 || strcmp(cmd, "d") == 0){
        //     char addr[20];
        //     addr[0] = '\0';
        //     sscanf(s.c_str(), "%s %s", cmd, addr);
        //     sdb_disasm(sdb, addr);
        // }
        // else if(strcmp(cmd, "dump") == 0 || strcmp(cmd, "x") == 0){
        //     char addr[20];
        //     addr[0] = '\0';
        //     sscanf(s.c_str(), "%s %s", cmd, addr);
        //     sdb_dump(sdb, addr);
        // }
        // else if(strcmp(cmd, "exit") == 0 || strcmp(cmd, "q") == 0){
        //     sdb_exit(sdb);
        //     break;
        // }
        // else if(strcmp(cmd, "get") == 0 || strcmp(cmd, "g") == 0){
        //     char reg[16];
        //     sscanf(s.c_str(), "%s %s", cmd, reg);
        //     sdb_get(sdb, reg);
        // }
        // else if(strcmp(cmd, "getregs") == 0){
        //     sdb_getregs(sdb);
        // }
        // else if(strcmp(cmd, "help") == 0 || strcmp(cmd, "h") == 0){
        //     sdb_help();
        // }
        // else if(strcmp(cmd, "list") == 0 || strcmp(cmd, "l") == 0){
        //     sdb_list(sdb);
        // }
        // else if(strcmp(cmd, "load") == 0){
        //     char filename[64];
        //     sscanf(s.c_str(), "%s %s", cmd, filename);
        //     sdb_load(sdb, filename);
        // }
        // else if(strcmp(cmd, "run") == 0 || strcmp(cmd, "r") == 0){
        //     sdb_run(sdb);
        // }
        // else if(strcmp(cmd, "vmmap") == 0 || strcmp(cmd, "m") == 0){
        //     sdb_vmmap(sdb);
        // }
        // else if(strcmp(cmd, "set") == 0 || strcmp(cmd, "s") == 0){
        //     char reg[16], val_c[20];
        //     sscanf(s.c_str(), "%s %s %s", cmd, reg, val_c);
        //     sdb_set(sdb, reg, str_to_ull(val_c));
        // }
        // else if(strcmp(cmd, "si") == 0){
        //     sdb_si(sdb);
        // }
        // else if(strcmp(cmd, "start") == 0){
        //     sdb_start(sdb);
        // }
        // else{
        //     printf("Undefined command: \"%s\".  Try \"help\".\n", cmd);
        // }
    }
    return 0;
}