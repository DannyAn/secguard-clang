
#include <windows.h>
#include <stdio.h>


void run_user_command(const char *user_input) {
    char cmd[256];

    
    wsprintfA(cmd, "cmd.exe /c %s", user_input);
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}


void write_user_file(const char *filename) {
    char path[MAX_PATH];

    
    GetTempPathA(MAX_PATH, path);
    strcat(path, filename);
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
}


void create_temp_file_unsafe() {
    char path[MAX_PATH];
    char temp_file[MAX_PATH];

    
    GetTempPathA(MAX_PATH, path);
    GetTempFileNameA(path, "SG", 0, temp_file);
    HANDLE h = CreateFileA(temp_file, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
}


void drop_and_elevate() {
    HANDLE hToken;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {

        
    }
}

void impersonate_logged_on_user() {

    HANDLE hToken;
    if (ImpersonateLoggedOnUser(hToken)) {

        
        RevertToSelf();
    }
}


void store_registry_credential() {

    HKEY hKey;
    RegCreateKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\MyApp", 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);

    RegSetValueExA(hKey, "Password", 0, REG_SZ,
        (BYTE*)"P@ssw0rd!", 9);
    RegCloseKey(hKey);
}


void allocate_user_size(DWORD user_size) {

    
    LPVOID mem = VirtualAlloc(NULL, user_size,
                              MEM_COMMIT, PAGE_READWRITE);
    if (mem) {

        VirtualFree(mem, 0, MEM_RELEASE);
    }
}

int main() {
    printf("Windows vulnerability demo\n");
    run_user_command("dir C:\\");
    write_user_file("..\\..\\Windows\\System32\\test.txt");
    create_temp_file_unsafe();
    store_registry_credential();
    allocate_user_size(1024 * 1024);
    return 0;
}
