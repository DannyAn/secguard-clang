//go:build !nosqlite

package planner

import "testing"

// A.7a: the command-initialization idiom `#define MSG_INIT do { a = 0; b = 0; c
// = 0; } while (0)` invoked right after the declarations writes those locals.
// The uninit detector must not auto-confirm a use-before-init for a variable the
// object-like macro assigns.
func TestUninit_ObjectMacroInitWritesLocals(t *testing.T) {
	src := `#include <stdint.h>

#define MSG_INIT do { paraNum = 0; execId = 0; errCode = 0; } while (0)

int handler(void *msg)
{
    uint32_t paraNum, execId, errCode;
    MSG_INIT;
    (void)msg;
    (void)paraNum;
    (void)execId;
    return (int)errCode;
}

int real_uninit_bug(void)
{
    uint32_t errCode;
    return (int)errCode;
}
`
	result := planUninitMacroFiles(t, map[string]string{"msg.c": src})
	if c := candidateForFunc(t, result, "handler"); c != nil {
		t.Errorf("handler must NOT be flagged (MSG_INIT assigns errCode), got var=%s level=%s line=%d",
			c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
	if c := candidateForFunc(t, result, "real_uninit_bug"); c == nil {
		t.Fatalf("real_uninit_bug must stay flagged (control), got %s", candidateNames(result))
	}
}
