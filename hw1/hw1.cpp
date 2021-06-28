#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fstream>
#include <dirent.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <map>
#include <regex.h>
#include <vector>

using namespace std;
 
struct open_file_info{
    string COMMAND;
    string PID;
    string USER;
    string FD;
    string TYPE;
    long long int NODE;
    string NAME;
};

bool wrong_input = false, arg_c = false, arg_t = false, arg_f = false;
map<string, string> arg_map = {{"c", ""}, {"t", ""}, {"f", ""}};
void parse_command_line(int argc, char *argv[]);
void print_for_argu(open_file_info);
string get_comm(string);
string get_user(string);
open_file_info get_type_node(open_file_info, string);
open_file_info get_cwd_root_exe(open_file_info, string, string);
bool is_in_vector(vector<long long int>, long long int);
void get_maps(open_file_info, string, vector<long long int>);
void get_fd(open_file_info, string, string);
void get_pid_info(char *);

int main(int argc, char *argv[]){
    parse_command_line(argc, argv); // handel argument
    if(wrong_input) return 0;

    char *row[] = {(char*)"COMMNAD", (char*)"PID", (char*)"USER", (char*)"FD", (char*)"TYPE", (char*)"NODE", (char*)"NAME"};
    printf("%-36s%-8s%-12s%-8s%-12s%-8s%s\n", row[0], row[1], row[2], row[3], row[4], row[5], row[6]);
    get_pid_info((char*)"/proc"); // get all running process

    return 0;
}

void parse_command_line(int argc, char *argv[]){
    int c;
    while((c = getopt(argc, argv, "c:t:f:")) != -1){
        switch(c){
            case 'c':
                arg_c = true;
                arg_map["c"] = string(optarg);
                break;
            case 't':
                arg_t = true;
                if(strcmp(optarg, "DIR") && strcmp(optarg, "REG") && strcmp(optarg, "CHR") && 
                   strcmp(optarg, "FIFO") && strcmp(optarg, "SOCK") && strcmp(optarg, "unknown")){
                    cout << "Invalid TYPE option." << endl;
                    wrong_input = true;
                }
                arg_map["t"] = string(optarg);
                break;
            case 'f':
                arg_f = true;
                arg_map["f"] = string(optarg);
                break;
            default:
                cout << "Usage : ./hw1 [-c REGEX] [-t TYPE] [-f REGEX]" << endl;
                wrong_input = true;
                break;
        }
    }
    return;
}

void print_for_argu(open_file_info ofi){
    if(arg_c){
        int status;
        regex_t r;
        regmatch_t pmatch[10];
        size_t nmatch = 10;
        int cflags = REG_EXTENDED;
        regcomp(&r, arg_map["c"].c_str(), cflags);
        status = regexec(&r, ofi.COMMAND.c_str(), nmatch, pmatch, 0);
        if(status != 0) // not match
            return;
    }
    if(arg_t){
        if(strcmp(ofi.TYPE.c_str(), arg_map["t"].c_str()))
            return;
        // else printf("type correct\n");
    }
    if(arg_f){
        int status;
        regex_t r;
        regmatch_t pmatch[10];
        size_t nmatch = 10;
        int cflags = REG_EXTENDED;
        regcomp(&r, arg_map["f"].c_str(), cflags);
        status = regexec(&r, ofi.NAME.c_str(), nmatch, pmatch, 0);
        if(status != 0) // not match
            return;
    }
    if(ofi.NODE == -1)
        printf("%-36s%-8s%-12s%-8s%-12s%-8s%s\n", 
                    ofi.COMMAND.c_str(), ofi.PID.c_str(), ofi.USER.c_str(), ofi.FD.c_str(),
                    ofi.TYPE.c_str(), "", ofi.NAME.c_str());
    else
        printf("%-36s%-8s%-12s%-8s%-12s%-8lld%s\n", 
                    ofi.COMMAND.c_str(), ofi.PID.c_str(), ofi.USER.c_str(), ofi.FD.c_str(),
                    ofi.TYPE.c_str(), ofi.NODE, ofi.NAME.c_str());
    return;
}

string get_comm(string path){
    ifstream f(path, ifstream::in);
    if(!f){
        // fprintf(stderr, "Can't open %s\n", path.c_str());
        return "open_fail";
    }
    string comm;
    f >> comm;
    // int pos = comm.find_first_of(":", 0);
    // if(pos>0){
    //     comm.erase(pos);
    // }
    return comm;
}

string get_user(string path){
    char buf[256];
    int uid;
    ifstream f(path, ifstream::in);
    if(!f){
        // fprintf(stderr, "Can't open %s\n", path.c_str());
        return "open_fail";
    }
    while(1){
        f >> buf;
        if(strcmp(buf, "Uid:") == 0){
            f >> buf;
            // cout << "Uid:" << buf << endl;
            break;
        }
    }
    uid = atoi(buf);

    struct passwd *user;
    user = getpwuid(uid);

    return user->pw_name;
}

open_file_info get_type_node(open_file_info ofi, string path){
    struct stat s;
    stat(path.c_str(), &s);
    ofi.NODE = s.st_ino;
    if((s.st_mode & S_IFMT) == S_IFDIR) ofi.TYPE = "DIR";
    else if((s.st_mode & S_IFMT) == S_IFREG) ofi.TYPE = "REG";
    else if((s.st_mode & S_IFMT) == S_IFCHR) ofi.TYPE = "CHR";
    else if((s.st_mode & S_IFMT) == S_IFIFO) ofi.TYPE = "FIFO";
    else if((s.st_mode & S_IFMT) == S_IFSOCK) ofi.TYPE = "SOCK";
    else ofi.TYPE = "unknown";
    return ofi;
}

open_file_info get_cwd_root_exe(open_file_info ofi, string path, char *dir_name){
    ofi.FD = string(dir_name);

    ssize_t link_dest_size;
    char link_dest[PATH_MAX];
    if((link_dest_size = readlink(path.c_str(), link_dest, sizeof(link_dest)-1)) < 0){
        if(errno != ENOENT)
            snprintf(link_dest, sizeof(link_dest), "%s (readlink: %s)", path.c_str(), strerror(errno));
        else
            snprintf(link_dest, sizeof(link_dest), "%s", path.c_str());
    }
    else{
        link_dest[link_dest_size] = '\0';
    }
    ofi.NAME = (string)link_dest;

    if(link_dest_size < 0){
        ofi.TYPE = "unknown";
        ofi.NODE = -1;
        if((arg_c == 1) || (arg_t == 1) || (arg_f == 1))
            print_for_argu(ofi);
        else
            printf("%-36s%-8s%-12s%-8s%-12s%-8s%s\n", 
                    ofi.COMMAND.c_str(), ofi.PID.c_str(), ofi.USER.c_str(), ofi.FD.c_str(),
                    ofi.TYPE.c_str(), "", ofi.NAME.c_str());
    }
    else{
        ofi = get_type_node(ofi, path);
        if(string(link_dest).find("(deleted)") != string(link_dest).npos){
            // printf("\n\nfind---------------------------------------\n\n");
            ofi.TYPE = "unknown";
        }

        if((arg_c == 1) || (arg_t == 1) || (arg_f == 1))
            print_for_argu(ofi);
        else
            printf("%-36s%-8s%-12s%-8s%-12s%-8lld%s\n", 
                ofi.COMMAND.c_str(), ofi.PID.c_str(), ofi.USER.c_str(), ofi.FD.c_str(),
                ofi.TYPE.c_str(), ofi.NODE, ofi.NAME.c_str());
    }
    return ofi;
}

bool is_in_vector(vector<long long int> maps_inode, long long int inode){
    vector<long long int>::iterator it;
    for(it = maps_inode.begin(); it != maps_inode.end(); it++){
        if(*it == inode)
            return true;
    }
    return false;
}

void get_maps(open_file_info ofi, string path, vector<long long int> maps_inode){
    ofi.TYPE = "REG";
    
    // FILE *f;
    // f = fopen(path.c_str(), "r");
    ifstream f(path.c_str(), ifstream::in);
    if(!f) return;
    char buf[1024], device[10];
    long long int inode;
    char file[PATH_MAX];
    while(f){
        ofi.FD = "mem";
        f.getline(buf, sizeof(buf));
        if(sscanf(buf, "%*x-%*x %*s %*zx %5s %lld %s\n", device, &inode, file)!=3)
            continue;
        if(inode == 0 || !strcmp(device, "00:00")|| is_in_vector(maps_inode, inode))
            continue;
        maps_inode.push_back(inode);

        if(string(buf).find("(deleted)") != string(buf).npos){
            ofi.FD = "del";
            ofi.TYPE = "unknown";
        }

        ofi.NODE = inode;
        ofi.NAME = string(file);
        
        if((arg_c == 1) || (arg_t == 1) || (arg_f == 1))
            print_for_argu(ofi);
        else
            printf("%-36s%-8s%-12s%-8s%-12s%-8lld%s\n", 
                    ofi.COMMAND.c_str(), ofi.PID.c_str(), ofi.USER.c_str(), ofi.FD.c_str(),
                    ofi.TYPE.c_str(), ofi.NODE, ofi.NAME.c_str());
    }
    return;
}

void get_fd(open_file_info ofi, string path, string parent_path){
    DIR *dir;
    struct dirent *ptr;

    dir = opendir(path.c_str());
    if(dir == NULL){
        char msg[1024];
        snprintf(msg, sizeof(msg), "%s (opendir: %s)", path.c_str(), strerror(errno));
        ofi.FD = "NOFD";
        ofi.TYPE = "";
        ofi.NODE = -1;
        if((arg_c == 1) || (arg_t == 1) || (arg_f == 1))
            print_for_argu(ofi);
        else
            printf("%-36s%-8s%-12s%-8s%-12s%-8s%s\n", 
                    ofi.COMMAND.c_str(), ofi.PID.c_str(), ofi.USER.c_str(), ofi.FD.c_str(),
                    ofi.TYPE.c_str(), "", msg);
    }
    else{
        while((ptr = readdir(dir)) != NULL){
            if(!strcmp(ptr->d_name, ".") || !strcmp(ptr->d_name, ".."))
                continue;
            string fd_path = path + "/" + string(ptr->d_name); // proc/pid/fd/N

            ssize_t link_dest_size;
            char link_dest[PATH_MAX];
            if((link_dest_size = readlink(fd_path.c_str(), link_dest, sizeof(link_dest)-1)) < 0)
                continue;
            
            link_dest[link_dest_size] = '\0';
            
            string fdinfo_path = parent_path + "/fdinfo/" + string(ptr->d_name);
            ifstream f(fdinfo_path.c_str(), ifstream::in);
            if(!f) return;
            char buf[1024];
            int flags;
            while(f){
                f.getline(buf, sizeof(buf));
                if(sscanf(buf, "flags: %d", &flags)==1)
                    break;
            }
            if((flags&O_ACCMODE) == O_RDONLY)
                ofi.FD = string(ptr->d_name) + "r";
            else if((flags&O_ACCMODE) == O_WRONLY)
                ofi.FD = string(ptr->d_name) + "w";
            else if((flags&O_ACCMODE) == O_RDWR)
                ofi.FD = string(ptr->d_name) + "u";

            ofi.NAME = string(link_dest);

            ofi = get_type_node(ofi, fd_path);
            if(string(link_dest).find("(deleted)") != string(link_dest).npos){
                // printf("\n\nfind---------------------------------------\n\n");
                ofi.TYPE = "unknown";
            }
            if(string(link_dest).find("anon_inode") != string(buf).npos){
                char str[256];
                sprintf(str, "%lld", ofi.NODE);
                ofi.NAME = "anon_inode:[" + string(str) + "]";
            }

            if((arg_c == 1) || (arg_t == 1) || (arg_f == 1))
                print_for_argu(ofi);
            else
                printf("%-36s%-8s%-12s%-8s%-12s%-8lld%s\n", 
                    ofi.COMMAND.c_str(), ofi.PID.c_str(), ofi.USER.c_str(), ofi.FD.c_str(),
                    ofi.TYPE.c_str(), ofi.NODE, ofi.NAME.c_str());
        }
    }
    return;
}

void get_pid_info(char dirname[]){
    DIR *dir;
    struct dirent *ptr;

    dir = opendir(dirname);
    if(dir == NULL){
        fprintf(stderr, "Can't open %s\n", dirname);
        return;
    }
    else{
        while((ptr = readdir(dir)) != NULL){
            string dir_name = ptr->d_name;
            if(dir_name[0] >= 48 && dir_name[0] <= 57){ // get all pid in /proc


                open_file_info ofi; // get pid
                ofi.PID = ptr->d_name;
                // cout << ofi.PID << " ";

                string path;
                path = string("/proc/") + ptr->d_name + string("/comm"); // get command
                ofi.COMMAND = get_comm(path);
                // cout << ofi.COMMAND << " ";

                path = string("/proc/") + ptr->d_name + string("/status"); // get user
                ofi.USER = get_user(path);
                // cout << ofi.USER << " ";

                if(!strcmp(ofi.COMMAND.c_str(), "open_fail") || !strcmp(ofi.USER.c_str(), "open_fail"))
                    continue;
                
                path = string("/proc/") + ptr->d_name + string("/cwd"); // /proc/pid/cwd
                ofi = get_cwd_root_exe(ofi, path, (char*)"cwd");

                path = string("/proc/") + ptr->d_name + string("/root"); // /proc/pid/root
                ofi = get_cwd_root_exe(ofi, path, (char*)"root");

                path = string("/proc/") + ptr->d_name + string("/exe"); // /proc/pid/exe
                ofi = get_cwd_root_exe(ofi, path, (char*)"exe");

                vector<long long int> maps_inode;
                maps_inode.push_back(ofi.NODE);
                path = string("/proc/") + ptr->d_name + string("/maps"); // /proc/pid/maps
                get_maps(ofi, path, maps_inode);

                path = string("/proc/") + ptr->d_name + string("/fd"); // /proc/pid/fd
                string parent_path = string("/proc/") + ptr->d_name;
                get_fd(ofi, path, parent_path);
            }
        }
        closedir(dir);
    }
    return;
}

