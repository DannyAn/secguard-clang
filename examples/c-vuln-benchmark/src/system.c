
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>


void execute_user_command(const char *user_input) {
    char cmd[256];

    
    snprintf(cmd, sizeof(cmd), "grep '%s' /var/log/syslog", user_input);
    system(cmd);
}

void execute_safe(const char *user_input) {
    
    char *const argv[] = {"/bin/grep", user_input, "/var/log/syslog", NULL};
    
    printf("execve would be called here with validated args\n");
}


void read_user_file(const char *filename) {
    char path[512];

    
    snprintf(path, sizeof(path), "/var/data/%s", filename);
    FILE *f = fopen(path, "r");
    if (f) {
        char buf[256];
        while (fgets(buf, sizeof(buf), f)) printf("%s", buf);
        fclose(f);
    }
}


void check_then_open(const char *path) {
    struct stat st;

    
    if (access(path, R_OK) == 0) {  
        
        FILE *f = fopen(path, "r");  
        if (f) {
            char buf[256];
            while (fgets(buf, sizeof(buf), f)) printf("%s", buf);
            fclose(f);
        }
    }
}

void toctou_safe(const char *path) {
    
    int dir_fd = open("/safe_dir", O_RDONLY);
    if (dir_fd >= 0) {
        int fd = openat(dir_fd, path, O_RDONLY | O_NOFOLLOW);
        if (fd >= 0) close(fd);
        close(dir_fd);
    }
}


void create_temp_file_unsafe() {
    char template[] = "/tmp/prefixXXXXXX";

    
    
    FILE *f = fopen("/tmp/myapp.log", "w");
    if (f) {
        fprintf(f, "temporary data\n");
        fclose(f);
    }
}

void create_temp_file_safe() {
    
    char template[] = "/tmp/myapp_XXXXXX";
    int fd = mkstemp(template);
    if (fd >= 0) {
        write(fd, "safe temp data\n", 15);
        close(fd);
    }
}


void write_log_unsafe() {

    
    
    FILE *f = fopen("/var/log/myapp.log", "a");
    if (f) {
        fprintf(f, "log entry\n");
        fclose(f);
    }
}

void write_log_safe() {
    
    int fd = open("/var/log/myapp.log", O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0644);
    if (fd >= 0) {
        write(fd, "safe log entry\n", 15);
        close(fd);
    }
}


void setuid_and_revert() {

    

    
    if (seteuid(65534) != 0) {  
        perror("seteuid failed");
        return;
    }

    
    printf("Running as uid: %d\n", geteuid());


    
    seteuid(0);

    printf("Now running as uid: %d (back to root!)\n", geteuid());
}

void setuid_permanent() {
    
    if (setuid(65534) != 0) {
        perror("setuid failed");
        return;
    }
    
    printf("Permanently running as uid: %d\n", geteuid());
}

int main() {
    printf("System security vulnerability demo\n");
    printf("This file demonstrates 6 CWE types\n");
    return 0;
}
