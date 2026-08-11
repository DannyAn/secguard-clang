package evidence

import (
	"context"
	"strings"
	"testing"
)

func TestInjection_CreateProcessA(t *testing.T) {
	store := runIndexAndDetect(t, "tc19_cmd_injection_createprocess.c")
	assertHasEvent(t, store, "INJECTION", "CreateProcessA")
}

func TestInjection_TaintFlow_WsprintfCreateProcess(t *testing.T) {
	store := runIndexAndDetect(t, "tc19_cmd_injection_createprocess.c")
	ctx := context.Background()
	events, _ := store.ListEventsByType(ctx, "INJECTION")
	found := false
	for _, e := range events {
		if strings.Contains(e.Properties, `"taint":"flow"`) {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected INJECTION event with taint=flow for wsprintfA→CreateProcessA pattern")
	}
}

func TestInjection_CommandInjectionSinks(t *testing.T) {
	expected := []string{"system", "popen", "CreateProcessA", "CreateProcessW",
		"ShellExecuteA", "ShellExecuteW", "execl", "execlp", "execle", "execv", "execvp"}
	for _, api := range expected {
		if !commandInjectionSinks[api] {
			t.Errorf("%s should be in commandInjectionSinks", api)
		}
	}
}
