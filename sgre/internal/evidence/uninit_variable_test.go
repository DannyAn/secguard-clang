package evidence

import (
	"testing"
)

func TestUninit_RegcompOutputParam(t *testing.T) {
	store := runIndexAndDetect(t, "tc18_output_param_regcomp.c")
	assertNoEvent(t, store, "VALUE_USE", "RegcompOutputParam")
}

func TestUninit_NeverAssignedFlag(t *testing.T) {
	store := runIndexAndDetect(t, "tc21_uninit_flag.c")
	assertHasEvent(t, store, "VALUE_USE", "UninitFlag")
}

func TestUninit_OutputParamInitializersExpanded(t *testing.T) {
	expected := []string{"regcomp", "regexec", "OpenProcessToken", "GetTokenInformation",
		"RegCreateKeyExA", "RegOpenKeyExA", "GetTempPathA", "GetTempFileNameA",
		"stat", "fstat", "lstat", "gettimeofday", "clock_gettime",
		"strtol", "strtoul", "wcstombs"}
	for _, api := range expected {
		if !isOutputParamInitializer(api) {
			t.Errorf("%s should be in outputParamInitializers", api)
		}
	}
}

func TestUninit_ExistingInitializersPreserved(t *testing.T) {
	existing := []string{"pthread_create", "DES_set_key_unchecked", "DES_set_key_checked",
		"pthread_mutex_init", "pthread_cond_init", "pthread_rwlock_init", "sem_init"}
	for _, api := range existing {
		if !isOutputParamInitializer(api) {
			t.Errorf("%s should still be in outputParamInitializers (regression)", api)
		}
	}
}
