//go:build !nosqlite

package evidence

import "testing"

// TestUninit_LocaltimeOutParam pins the POSIX time out-param fix: localtime_r /
// gmtime_r fill their `struct tm *` argument, so a later field read is
// initialized and must NOT be flagged. A fully-uninitialized struct field read is
// still flagged (the control proves the detector still catches genuine uninit).
func TestUninit_LocaltimeOutParam(t *testing.T) {
	store := runIndexAndDetect(t, "tc130_uninit_localtime_outparam.c")
	valueUseByFunc, _ := countEventsByFunction(t, store, "VALUE_USE", "VALUE_INIT")

	if valueUseByFunc["get_year"] != 0 {
		t.Errorf("get_year: localtime_r fills local_tm, the field read must not be flagged, got %d VALUE_USE", valueUseByFunc["get_year"])
	}
	if valueUseByFunc["get_hour_gm"] != 0 {
		t.Errorf("get_hour_gm: gmtime_r fills g_tm, the field read must not be flagged, got %d VALUE_USE", valueUseByFunc["get_hour_gm"])
	}
	if valueUseByFunc["no_init"] == 0 {
		t.Errorf("no_init: a genuinely uninitialized field read must still be flagged, got 0 VALUE_USE")
	}
}
