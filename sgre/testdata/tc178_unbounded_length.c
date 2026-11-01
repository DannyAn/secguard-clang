#include <string.h>

int ul01_recv_malloc(int sock) {
    int len = recv(sock, 0, 0, 0);
    char *buf = malloc(len);
    return buf != 0;
}

int ul10_guarded(int sock) {
    int len = recv(sock, 0, 0, 0);
    if (len > 4096) return -1;
    char *buf = malloc(len);
    return buf != 0;
}

int main(void) {
    return ul01_recv_malloc(0) + ul10_guarded(0);
}
