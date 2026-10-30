package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/planner"
)

func TestSortCandidatesByFunction(t *testing.T) {
	cands := []planner.EvidenceItem{
		{Target: planner.TargetInfo{File: "a.c", Function: "b", Line: 1, Variable: "x"}},
		{Target: planner.TargetInfo{File: "a.c", Function: "a", Line: 1, Variable: "x"}},
		{Target: planner.TargetInfo{File: "b.c", Function: "b", Line: 1, Variable: "y"}},
		{Target: planner.TargetInfo{File: "a.c", Function: "a", Line: 2, Variable: "y"}},
	}
	sortCandidatesByFunction(cands)

	var got []string
	for _, c := range cands {
		got = append(got, c.Target.Function+c.Target.Variable)
	}
	want := []string{"ax", "ay", "bx", "by"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestWriteTypeIndexClustersByFunction(t *testing.T) {
	dir := t.TempDir()
	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test"}
	pkg := &planner.PlanResult{
		VulnerabilityType: "null-deref",
		Candidates: []planner.EvidenceItem{
			{Target: planner.TargetInfo{File: "/repo/src/a.c", Function: "funcB", Line: 11, Variable: "b1"}, SuspicionLevel: "suspected", Hint: "—"},
			{Target: planner.TargetInfo{File: "/repo/src/a.c", Function: "funcA", Line: 12, Variable: "a1"}, SuspicionLevel: "suspected", Hint: "—"},
			{Target: planner.TargetInfo{File: "/repo/src/b.c", Function: "funcB", Line: 21, Variable: "b2"}, SuspicionLevel: "suspected", Hint: "—"},
			{Target: planner.TargetInfo{File: "/repo/src/b.c", Function: "funcA", Line: 22, Variable: "a2"}, SuspicionLevel: "suspected", Hint: "—"},
		},
	}
	if err := o.writeCandidates([]*planner.PlanResult{pkg}); err != nil {
		t.Fatal(err)
	}

	indexPath := filepath.Join(dir, CandidatesDir, "null-deref", TypeIndexFile)
	data, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}

	var funcs []string
	var evidence []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "| ") || strings.HasPrefix(line, "| #") || strings.HasPrefix(line, "|---") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) < 9 {
			continue
		}
		funcs = append(funcs, strings.TrimSpace(cells[2]))
		evidence = append(evidence, strings.Trim(strings.TrimSpace(cells[8]), "`"))
	}

	want := []string{"funcA", "funcA", "funcB", "funcB"}
	if len(funcs) != len(want) {
		t.Fatalf("index row count = %d, want %d\n%s", len(funcs), len(want), string(data))
	}
	for i := range want {
		if funcs[i] != want[i] {
			t.Fatalf("index not clustered: functions=%v want=%v\n%s", funcs, want, string(data))
		}
	}

	// The Evidence column must name a real on-disk file with a sequential NNN
	// that matches the row's # — i.e. the # column, the Evidence column, and the
	// NNN_*.md filenames stay one consistent order after clustering.
	for i, name := range evidence {
		wantPrefix := fmt.Sprintf("%03d_", i+1)
		if !strings.HasPrefix(name, wantPrefix) {
			t.Fatalf("evidence %q must be the %d-th file (prefix %q)", name, i+1, wantPrefix)
		}
		path := filepath.Join(dir, CandidatesDir, "null-deref", name)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("evidence file %q does not exist: %v", name, err)
		}
	}
}
