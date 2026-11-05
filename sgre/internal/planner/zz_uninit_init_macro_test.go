//go:build !nosqlite

package planner

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/macros"
)

// A command-init macro whose body assigns caller locals that are NOT its
// arguments (`CMD_MSG_INIT(recv)` → `execId = get_exec_id(recv)`) initializes
// them. The uninit detector/planner must not auto-confirm `init@none` reads for
// those locals; the previous behaviour produced CWE-457 false positives in
// command handlers (Issue #214, shape 1).
func TestUninit_CommandInitMacroWritesCallerLocals(t *testing.T) {
	src := `#include <stdint.h>

extern uint32_t get_exec_id(uint32_t msgRcv);
extern uint32_t get_para_num(uint32_t msgRcv);

#define CMD_MSG_INIT(recv) do { \
    execId = get_exec_id(recv); \
    paraNum = get_para_num(recv); \
} while (0)

uint32_t cmd_show_process(uint32_t msgRcv)
{
    uint32_t execId;
    uint32_t paraNum;
    CMD_MSG_INIT(msgRcv);
    return execId + paraNum;
}

uint32_t real_uninit(uint32_t msgRcv)
{
    uint32_t errCode;
    return errCode + msgRcv;
}
`
	result := planUninitMacroFiles(t, map[string]string{"cmd_msg.c": src})
	if c := candidateForFunc(t, result, "cmd_show_process"); c != nil {
		t.Errorf("cmd_show_process must NOT be flagged (CMD_MSG_INIT initializes execId/paraNum), got var=%s level=%s",
			c.Target.Variable, c.SuspicionLevel)
	}
	// Control: a variable the macro does not assign stays a real certain-uninit.
	c := candidateForFunc(t, result, "real_uninit")
	if c == nil {
		t.Fatalf("real_uninit must stay flagged, got %s", candidateNames(result))
	}
	if c.SuspicionLevel != "confirmed" {
		t.Errorf("real_uninit: suspicion = %q, want confirmed (control)", c.SuspicionLevel)
	}
}

// When the init macro's body lives outside the scan tree, the pipeline cannot
// prove which locals it writes. An `init@none` read in its context window is not
// certain — it is demoted to suspected for AI review instead of being filed as a
// machine-confirmed CWE-457.
func TestUninit_UnknownInitMacroDemotesToSuspected(t *testing.T) {
	src := `#include <stdint.h>

extern void MSG_CTX_INIT(uint32_t recv);

uint32_t cmd_unknown_init(uint32_t msgRcv)
{
    uint32_t execId;
    MSG_CTX_INIT(msgRcv);
    return execId;
}
`
	result := planUninitMacroFiles(t, map[string]string{"cmd_unknown.c": src})
	c := candidateForFunc(t, result, "cmd_unknown_init")
	if c == nil {
		t.Fatalf("cmd_unknown_init must stay a candidate (demoted, not dropped), got %s", candidateNames(result))
	}
	if c.SuspicionLevel != "suspected" {
		t.Errorf("suspicion = %q, want suspected (unknown init macro may assign execId)", c.SuspicionLevel)
	}
}

// A project declares the macro in [uninit] initialization_macros when its body
// is outside the scan tree. The explicit contract lets the planner treat the
// locals declared before the call as initialized, so the false positive is
// dismissed instead of reaching the AI at all.
func TestUninit_ConfiguredInitMacroInitializesDeclarations(t *testing.T) {
	macros.RegisterInitializationMacros([]string{"zz_test_ctx_setup"})
	src := `#include <stdint.h>

extern void zz_test_ctx_setup(uint32_t recv);

uint32_t cmd_configured_init(uint32_t msgRcv)
{
    uint32_t execId;
    zz_test_ctx_setup(msgRcv);
    return execId;
}
`
	result := planUninitMacroFiles(t, map[string]string{"cmd_cfg.c": src})
	if c := candidateForFunc(t, result, "cmd_configured_init"); c != nil {
		t.Errorf("cmd_configured_init must NOT be flagged (configured init macro initializes execId), got var=%s level=%s",
			c.Target.Variable, c.SuspicionLevel)
	}
}

// A C FUNCTION whose name ends in _init (`cmd_cfg_init`) is not an
// initialization macro, and its own definition line sits in the candidate's
// context window. The raw-source name heuristic must not demote every uninit
// read inside such a function.
func TestUninit_FunctionNamedInitIsNotAnInitMacro(t *testing.T) {
	src := `#include <stdint.h>

uint32_t cmd_cfg_init(void)
{
    uint32_t value;
    return value;
}
`
	result := planUninitMacroFiles(t, map[string]string{"cmd_fn_init.c": src})
	c := candidateForFunc(t, result, "cmd_cfg_init")
	if c == nil {
		t.Fatalf("cmd_cfg_init must stay flagged, got %s", candidateNames(result))
	}
	if c.SuspicionLevel != "confirmed" {
		t.Errorf("suspicion = %q, want confirmed (a function name is not a macro)", c.SuspicionLevel)
	}
}
