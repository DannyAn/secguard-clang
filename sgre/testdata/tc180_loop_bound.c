#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>

static void sink(int x) { (void)x; }

/* POSITIVE — a function parameter controls the loop bound with no upper guard. */
int lb01_param_bound(int count) {
    for (int i = 0; i < count; i++) {
        sink(i);
    }
    return 0;
}

/* POSITIVE — a network read return value controls the loop bound. */
int lb02_recv_bound(int sock) {
    int n = recv(sock, 0, 0, 0);
    for (int i = 0; i < n; i++) {
        char *p = malloc(64);
        free(p);
    }
    return 0;
}

/* POSITIVE — the bound is an overflow-prone product of two parameters. */
int lb03_mul_bound(unsigned int a, unsigned int b) {
    unsigned int count = a * b;
    for (unsigned int i = 0; i < count; i++) {
        sink(i);
    }
    return 0;
}

/* NEGATIVE — a constant-bound loop is finite by construction. */
int lb10_const_bound(void) {
    for (int i = 0; i < 100; i++) {
        sink(i);
    }
    return 0;
}

/* NEGATIVE — an early-return upper guard bounds the parameter. */
int lb11_guarded(int count) {
    if (count > 4096) {
        return -1;
    }
    for (int i = 0; i < count; i++) {
        sink(i);
    }
    return 0;
}

/* NEGATIVE — the bound is clamped before the loop. */
int lb12_clamped(int count) {
    if (count > 4096) {
        count = 4096;
    }
    for (int i = 0; i < count; i++) {
        sink(i);
    }
    return 0;
}

/* NEGATIVE — a resident loop has no countable ascending bound. */
void lb13_while1(void) {
    while (1) {
        sink(1);
    }
}

/* NEGATIVE — a descending loop is not an ascending bound. */
int lb14_descending(int n) {
    for (int i = n; i > 0; i--) {
        sink(i);
    }
    return 0;
}

/* NEGATIVE — a local constant assignment bounds the loop. */
int lb15_local_bound(void) {
    int count = 10;
    for (int i = 0; i < count; i++) {
        sink(i);
    }
    return 0;
}

/* NEGATIVE — a linked-list traversal is not a countable bound. */
int lb16_traversal(int *head) {
    int *p = head;
    while (p) {
        p = 0;
    }
    return 0;
}

int main(void) {
    return lb01_param_bound(0) + lb02_recv_bound(0) + lb03_mul_bound(0, 0) +
        lb10_const_bound() + lb11_guarded(0) + lb12_clamped(0) +
        lb14_descending(0) + lb15_local_bound() + lb16_traversal(0);
}
