#include <stdlib.h>
#include <stdint.h>

typedef struct { int x; } msg_data_t;
typedef struct { int unused; } stmt_t;

#define SQLITE_ROW 100

int blocking_step(stmt_t *s) { return 0; }
int get_record_num(stmt_t *s, uint8_t t) { return 5; }
void copy_data(msg_data_t *d, stmt_t *s, uint8_t t) {}
void RunDelay(int a, int b) {}
stmt_t *get_record_stmt(uint8_t t) { return (stmt_t *)1; }
void lock(void) {}
void unlock(void) {}

/* record_num is assigned on the first loop iteration (data starts NULL, so the
 * if (data == NULL) branch is guaranteed to run before any use) and reused on
 * later iterations. A naive CFG reachability sees the "skip the if block" path
 * via the loop back-edge and reports record_num as possibly uninitialized. */
msg_data_t *get_all_record(int *num, uint8_t get_type)
{
    lock();
    stmt_t *stmt = get_record_stmt(get_type);
    if (stmt == NULL) {
        *num = 0;
        unlock();
        return NULL;
    }
    msg_data_t *data = NULL;
    int record_num;
    int loop = 0;
    while (blocking_step(stmt) == SQLITE_ROW) {
        if (data == NULL) {
            record_num = get_record_num(stmt, get_type);
            int buf_size = record_num * (int)sizeof(msg_data_t);
            data = (buf_size > 0) ? (msg_data_t *)malloc(buf_size) : NULL;
            if (data == NULL) {
                break;
            }
        }
        if (loop >= record_num) {
            loop = record_num;
            break;
        }
        RunDelay(1000, 10);
        copy_data(data + loop, stmt, get_type);
        loop++;
    }
    unlock();
    *num = loop;
    return data;
}

/* Control: the lazy-init guard is NOT satisfied at loop entry (flag == 1, so
 * !flag is false), so v is genuinely uninitialized and must still be reported.
 * This pins that the loop-carried suppression does not over-suppress. */
int genuine_loop_uninit(int *out) {
    int v;
    int flag = 1;
    while (*out) {
        if (!flag) {
            v = 1;
        }
        *out = v;
        break;
    }
    return 0;
}
