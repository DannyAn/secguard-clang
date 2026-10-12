//go:build !nosqlite

package evidence

import "testing"

// TestUninit_AddrOutParamNilSummaryPanic pins the nil-*FuncSummary crash in the
// struct-partial-uninit path. outputParamInitializedVars reads
// summary.ParamWrites even when the call has no function summary, and a call
// that is a known output-param initializer OR has spec'd output arg indices
// (localtime_r/gmtime_r/gmtime_s) reaches that read without a summary. Taking
// the address of a NON-output argument (`localtime_r(&now, &tm_buf)`) made the
// specific-arg case false and fell through to the nil deref, panicking the whole
// uninit detector (reproduced on the redis codebase: seeds were emitted up to
// the panic and the type read as an incomplete "0 candidates").
//
// Without the fix this test panics; with it the detector completes and the
// genuine control case is still reported.
func TestUninit_AddrOutParamNilSummaryPanic(t *testing.T) {
	store := runIndexAndDetect(t, "tc131_uninit_addr_outparam.c")
	valueUseByFunc, _ := countEventsByFunction(t, store, "VALUE_USE", "VALUE_INIT")

	for _, fn := range []string{"localtime_addr", "gmtime_addr", "gmtime_s_addr"} {
		if n := valueUseByFunc[fn]; n != 0 {
			t.Errorf("%s: an output param at arg1 fills the struct, the field read must not be flagged, got %d VALUE_USE", fn, n)
		}
	}
	if valueUseByFunc["no_init"] == 0 {
		t.Errorf("no_init: a genuinely uninitialized struct field read must still be flagged, got 0 VALUE_USE")
	}
}
