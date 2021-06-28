#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
using namespace std;

const char *so_path = "./logger.so";
bool assign_output = false;
const char *file_output;
string cmd;

int main(int argc, char *argv[]){
    for(int i=1; i<argc; i++){
        if(argv[i][0] == '-'){
            if(argv[i][1] == 'o'){
                i++;
                file_output = argv[i];
                assign_output = true;
            }
            else if(argv[i][1] == 'p'){
                i++;
                so_path = argv[i];
            }
            else if(argv[i][1] == '-'){
                while(i != (argc-1)){
                    i++;
                    cmd = cmd + " " + string(argv[i]);
                }
                break;
            }
            else{
                fprintf(stderr, "%s: invalid option -- '%c'\n", argv[0], argv[i][1]);
                fprintf(stderr, "usage: ./logger [-o file] [-p sopath] [--] cmd [cmd args ...]\n");
                fprintf(stderr, "        -p: set the path to logger.so, default = ./logger.so\n");
                fprintf(stderr, "        -o: print output to file, print to \"stderr\" if no file specified\n");
                fprintf(stderr, "        --: separate the arguments for logger and for the command\n");
                cmd.clear();
                break;
            }
        }
        else{
            while(i != argc){
                cmd = cmd + " " + string(argv[i]);
                i++;
            }
            break;
        }
    }
    if(!cmd.empty()){
        if(assign_output)
            cmd = "LD_PRELOAD=" + string(so_path) + " " + cmd + " 2>" + string(file_output);
        else
            cmd = "LD_PRELOAD=" + string(so_path) + " " + cmd;
        system(cmd.c_str());
    }
    else
        fprintf(stderr, "no command given.\n");
    return 0;
}
