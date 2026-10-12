package apikb

import "testing"

func TestTruncatingWrapperCapArg_BuiltinAndPattern(t *testing.T) {
	for _, name := range []string{"snprintf_truncated_s", "sprintf_truncated_s", "vsprintf_truncated_s", "sprintf_s", "vsprintf_s"} {
		idx, ok := TruncatingWrapperCapArg(name)
		if !ok {
			t.Errorf("TruncatingWrapperCapArg(%q) = ok=false, want a truncating wrapper", name)
			continue
		}
		if idx != 1 {
			t.Errorf("TruncatingWrapperCapArg(%q) idx = %d, want 1 (the size argument)", name, idx)
		}
	}
	// snprintf / vsnprintf return the would-have-written count (unbounded), so
	// they must NOT be recognized as truncating wrappers.
	for _, name := range []string{"snprintf", "vsnprintf", "snprintf_s", "vsnprintf_s", "strlcpy", "strlcat"} {
		if _, ok := TruncatingWrapperCapArg(name); ok {
			t.Errorf("TruncatingWrapperCapArg(%q) = ok=true, want false (unbounded return)", name)
		}
	}
}

func TestRegisterTruncatingWrapper(t *testing.T) {
	RegisterTruncatingWrapper("nlog_syslog_add_pri", 1)
	idx, ok := TruncatingWrapperCapArg("nlog_syslog_add_pri")
	if !ok || idx != 1 {
		t.Errorf("registered wrapper nlog_syslog_add_pri = (%d, %v), want (1, true)", idx, ok)
	}
}
