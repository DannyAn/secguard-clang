
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sqlite3.h>


void safe_annex_k_functions(void) {
    char dst[256];
    char src[] = "user input";

    
    memcpy_s(dst, sizeof(dst), src, strlen(src) + 1);
    

    
    strcpy_s(dst, sizeof(dst), src);
    

    
    sprintf_s(dst, sizeof(dst), "value: %s", src);
    

    
    strcat_s(dst, sizeof(dst), "_suffix");
    
}


void safe_standard_functions(void) {
    char dst[256];
    char src[] = "user input";
    int written;

    
    written = snprintf(dst, sizeof(dst), "value: %s", src);
    if (written < 0 || (size_t)written >= sizeof(dst)) {
        return;  
    }
    
    

    
    strncpy(dst, src, sizeof(dst) - 1);
    dst[sizeof(dst) - 1] = '\0';  
    
    
}


void safe_command_execution(void) {
    
    char *argv[] = {"ping", "-c", "1", "127.0.0.1", NULL};
    execve("/bin/ping", argv, NULL);
    

    
    char *argv2[] = {"ls", "-la", NULL};
    execv("/bin/ls", argv2);
    
}


#ifdef __unix__
#include <bsd/string.h>
void safe_posix_functions(void) {
    char dst[256];
    char src[] = "user input";

    
    strlcpy(dst, src, sizeof(dst));
    
    

    
    strlcat(dst, "_suffix", sizeof(dst));
    
}
#endif


void safe_sql_query(sqlite3 *db, const char *username) {
    sqlite3_stmt *stmt;
    
    sqlite3_prepare_v2(db, "SELECT * FROM users WHERE name = ?", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
}
