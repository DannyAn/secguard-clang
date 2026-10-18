package planner

import (
	"strings"
	"testing"
)

// B4 rollout: the remaining §3.5 fact contracts. Each builder distills the
// machine-proven basis into (token, one-sentence judgment guide, origin) —
// no raw CFG/DFG, and the token must be the same one the hint emits.
func TestBuildVerdictFacts_B4Types(t *testing.T) {
	spec := func(name string) *VulnTypeSpec {
		s, err := GetVulnTypeSpec(name)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	tokens := func(facts []VerdictFact) string {
		parts := make([]string, 0, len(facts))
		for _, f := range facts {
			parts = append(parts, f.Token)
		}
		return strings.Join(parts, " ")
	}

	t.Run("divide-by-zero", func(t *testing.T) {
		facts := spec("divide-by-zero").BuildVerdictFacts(Candidate{
			VariableName: "count", DivisorInterval: "[0,100]", DivisorCallers: "3 direct call sites, 2 pass non-zero constants",
		})
		if got := tokens(facts); got != "divisor@bare range@[0,100] callers@3 direct call sites, 2 pass non-zero constants" {
			t.Errorf("tokens = %q", got)
		}
		if !strings.Contains(facts[1].Detail, "0 endpoint") {
			t.Errorf("range fact must target 0-endpoint reachability:\n%s", facts[1].Detail)
		}
	})

	t.Run("uninit", func(t *testing.T) {
		facts := spec("uninit").BuildVerdictFacts(Candidate{SuspicionLevel: "confirmed", Origin: "heap", DeclLine: 17})
		if got := tokens(facts); got != "certain-uninit origin@heap decl@17" {
			t.Errorf("tokens = %q", got)
		}
		if !strings.Contains(facts[0].Detail, "converged") {
			t.Errorf("certain fact must state the convergence:\n%s", facts[0].Detail)
		}
	})

	t.Run("uninit heap no in-function write fact", func(t *testing.T) {
		facts := spec("uninit").BuildVerdictFacts(Candidate{SuspicionLevel: "suspected", Origin: "heap_uninit", DeclLine: 18, InitWrite: "none"})
		if got := tokens(facts); got != "maybe-uninit origin@heap_uninit decl@18 init@unseen" {
			t.Fatalf("tokens = %q", got)
		}
		if !strings.Contains(facts[3].Detail, "allocating callee") {
			t.Errorf("init@unseen must name the callee/memset/output-param init path:\n%s", facts[3].Detail)
		}
	})

	t.Run("uninit loop-only write facts", func(t *testing.T) {
		facts := spec("uninit").BuildVerdictFacts(Candidate{SuspicionLevel: "suspected", Origin: "stack_uninit", DeclLine: 32, InitWrite: "loop", InitWriteLine: 33})
		if got := tokens(facts); got != "maybe-uninit origin@stack_uninit decl@32 init@33 may-skip" {
			t.Fatalf("tokens = %q", got)
		}
		if !strings.Contains(facts[3].Detail, "loop") || !strings.Contains(facts[4].Detail, "loop condition") {
			t.Errorf("loop facts must frame the loop-condition judgment:\n%s\n%s", facts[3].Detail, facts[4].Detail)
		}
	})

	t.Run("argument-type", func(t *testing.T) {
		facts := spec("argument-type").BuildVerdictFacts(Candidate{ExpectedType: "size_t", ActualType: "int", CastType: "size_t"})
		if got := tokens(facts); got != "expected@size_t actual@int cast@size_t" {
			t.Errorf("tokens = %q", got)
		}
		if !strings.Contains(facts[2].Detail, "intentional") {
			t.Errorf("cast fact must frame the judgment:\n%s", facts[2].Detail)
		}
	})

	t.Run("data-representation", func(t *testing.T) {
		facts := spec("data-representation").BuildVerdictFacts(Candidate{CastType: "unsigned int", Line: 30})
		if len(facts) != 1 || facts[0].Token != "cast@unsigned int" {
			t.Fatalf("tokens = %q", tokens(facts))
		}
		if !strings.Contains(facts[0].Detail, "truncation") {
			t.Errorf("cast fact must name the truncation/reinterpretation:\n%s", facts[0].Detail)
		}
	})

	t.Run("format-string", func(t *testing.T) {
		facts := spec("format-string").BuildVerdictFacts(Candidate{FormatArg: "user_fmt"})
		if len(facts) != 1 || facts[0].Token != "fmt-arg@user_fmt" {
			t.Fatalf("tokens = %q", tokens(facts))
		}
		if !strings.Contains(facts[0].Detail, "arbitrary format-specifier injection") {
			t.Errorf("fmt-arg fact:\n%s", facts[0].Detail)
		}
	})

	t.Run("path-traversal", func(t *testing.T) {
		facts := spec("path-traversal").BuildVerdictFacts(Candidate{PathExpr: "rel_path"})
		if len(facts) != 1 || facts[0].Token != "path-arg@rel_path" {
			t.Fatalf("tokens = %q", tokens(facts))
		}
		if !strings.Contains(facts[0].Detail, "../") {
			t.Errorf("path fact must name the traversal root:\n%s", facts[0].Detail)
		}
	})

	t.Run("hardcoded-secret", func(t *testing.T) {
		facts := spec("hardcoded-secret").BuildVerdictFacts(Candidate{SecretValue: "AKIAIOSFODNN7EXAMPLE"})
		if len(facts) != 1 || facts[0].Token != `value-shape@"AKIA…" (20 chars)` {
			t.Fatalf("tokens = %q", tokens(facts))
		}
		if strings.Contains(facts[0].Token, "OSFODNN7") {
			t.Errorf("the masked shape must not leak the literal's tail")
		}
	})

	t.Run("signal-handler", func(t *testing.T) {
		facts := spec("signal-handler").BuildVerdictFacts(Candidate{VariableName: "fprintf", FunctionName: "on_signal"})
		if len(facts) != 1 || facts[0].Token != "async-unsafe@fprintf" {
			t.Fatalf("tokens = %q", tokens(facts))
		}
		if !strings.Contains(facts[0].Detail, "async-signal-safe") {
			t.Errorf("fact must cite the POSIX list:\n%s", facts[0].Detail)
		}
	})

	t.Run("implicit-contract", func(t *testing.T) {
		facts := spec("implicit-contract").BuildVerdictFacts(Candidate{Subject: "ctx", CountField: "ctx->len", EvidenceKind: "self"})
		if got := tokens(facts); got != "subject@ctx count-field@ctx->len evidence-kind@self" {
			t.Errorf("tokens = %q", got)
		}
	})

	t.Run("sizeof-misuse", func(t *testing.T) {
		facts := spec("sizeof-misuse").BuildVerdictFacts(Candidate{VariableName: "ptr"})
		if len(facts) != 1 || facts[0].Token != "subject@ptr" {
			t.Fatalf("tokens = %q", tokens(facts))
		}
		if !strings.Contains(facts[0].Detail, "pointer width") {
			t.Errorf("fact must state the pointer-width defect:\n%s", facts[0].Detail)
		}
	})

	t.Run("double-free", func(t *testing.T) {
		facts := spec("double-free").BuildVerdictFacts(Candidate{
			FirstFree: 40, SecondFree: 52, MayFree: true, FirstCallee: "maybe_release",
		})
		if got := tokens(facts); got != "free@40,52 may-free cond@maybe_release" {
			t.Errorf("tokens = %q", got)
		}
		if !strings.Contains(facts[1].Detail, "possible, not must-proven") {
			t.Errorf("may-free fact must state the possibility tier:\n%s", facts[1].Detail)
		}
	})
}
