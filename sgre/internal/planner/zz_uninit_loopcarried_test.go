//go:build !nosqlite

package planner

import (
	"testing"
)

// End-to-end regression for the reported false positive: record_num is assigned
// on the first loop iteration (the guard `data == NULL` is guaranteed true at
// loop entry) and reused on later iterations, so the full pipeline must not
// surface it. The control function pins that a guard NOT satisfied at loop
// entry keeps a genuine uninit reported (no over-suppression).
const loopCarriedSrc = `#include <stdlib.h>
#include <stdint.h>

typedef struct { int x; } msg_data_t;
typedef struct { int unused; } stmt_t;

#define SQLITE_ROW 100

int blocking_step(stmt_t *s) { return 0; }
int get_record_num(stmt_t *s, uint8_t t) { return 5; }
stmt_t *get_record_stmt(uint8_t t) { return (stmt_t *)1; }

msg_data_t *get_all_record(int *num, uint8_t get_type)
{
    stmt_t *stmt = get_record_stmt(get_type);
    if (stmt == NULL) {
        *num = 0;
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
        loop++;
    }
    *num = loop;
    return data;
}

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
`

func TestUninit_LoopCarriedLazyInitEndToEnd(t *testing.T) {
	result := planUninitMacro(t, loopCarriedSrc)
	flagged := map[string]string{} // function -> variable
	for _, c := range result.Candidates {
		flagged[c.Target.Function] = c.Target.Variable
		if c.Target.Variable == "record_num" {
			t.Errorf("record_num must not be reported as uninit (loop-carried lazy init), got candidate at line %d", c.Target.Line)
		}
	}
	if flagged["genuine_loop_uninit"] != "v" {
		t.Errorf("genuine_loop_uninit's v must still be reported as uninit (guard not satisfied at loop entry), got %v", flagged)
	}
}
