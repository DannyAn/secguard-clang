package planner

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kongan/secguard-lite/internal/db"
)

func setupBenchmarkData(s *mockStore) {
	ctx := context.Background()
	fileID, _ := s.InsertFile(ctx, &db.File{Path: "benchmark/src", Language: "c"})

	p0Func, _ := s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "safe_annex_k_functions", StartLine: 1, EndLine: 20})
	p0Func2, _ := s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "safe_command_execution", StartLine: 21, EndLine: 30})
	p0Func3, _ := s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "safe_sql_query", StartLine: 31, EndLine: 50})

	p1Func, _ := s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "process_user_data", StartLine: 51, EndLine: 60})
	p1Func2, _ := s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "lookup_user", StartLine: 61, EndLine: 70})

	p2Func, _ := s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "copy_message", StartLine: 71, EndLine: 80})
	p2Func2, _ := s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "increment_counter", StartLine: 81, EndLine: 90})
	p2Func3, _ := s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "process_buffer", StartLine: 91, EndLine: 100})

	p3Func, _ := s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "run_admin_command", StartLine: 101, EndLine: 110})
	p3Func2, _ := s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "check_and_transfer", StartLine: 111, EndLine: 120})

	tpFunc, _ := s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "process_user_data_unsafe", StartLine: 121, EndLine: 130})
	tpFunc2, _ := s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "lookup_user_unsafe", StartLine: 131, EndLine: 140})

	insertBufferEvent := func(funcID int64, line int, funcName, category string) {
		locID, _ := s.InsertLocation(ctx, &db.Location{FileID: fileID, Line: line})
		props, _ := json.Marshal(map[string]string{"function": funcName, "category": category})
		s.InsertEvent(ctx, &db.SecurityEvent{EventType: "BUFFER_ACCESS", EntityID: funcID, LocationID: locID, Properties: string(props)})
	}
	insertGuardEvent := func(funcID int64, line int, cond string, strength string) {
		locID, _ := s.InsertLocation(ctx, &db.Location{FileID: fileID, Line: line})
		props, _ := json.Marshal(map[string]interface{}{"condition": cond, "scope_start": line, "scope_end": line + 10, "strength": strength})
		s.InsertEvent(ctx, &db.SecurityEvent{EventType: "NULL_GUARD", EntityID: funcID, LocationID: locID, Properties: string(props)})
	}

	insertBufferEvent(p0Func, 24, "memcpy_s", "buffer_overflow")
	insertBufferEvent(p0Func, 28, "strcpy_s", "buffer_overflow")
	insertBufferEvent(p0Func, 32, "sprintf_s", "buffer_overflow")
	insertBufferEvent(p0Func, 36, "strcat_s", "buffer_overflow")
	insertBufferEvent(p0Func, 44, "snprintf", "buffer_overflow")
	insertBufferEvent(p0Func2, 65, "execve", "command_injection")
	insertBufferEvent(p0Func3, 94, "sqlite3_prepare_v2", "sql_injection")

	insertBufferEvent(p1Func, 24, "SafeCopy_copy", "buffer_overflow")
	insertBufferEvent(p1Func, 31, "SafeCopy_strcpy", "buffer_overflow")
	insertBufferEvent(p1Func2, 38, "SafeQuery_exec", "command_injection")

	insertBufferEvent(p2Func, 28, "memcpy", "buffer_overflow")
	insertGuardEvent(p2Func, 27, "NULL_CHECK", "strong")
	insertBufferEvent(p2Func, 41, "memcpy", "buffer_overflow")
	insertGuardEvent(p2Func, 40, "NULL_CHECK", "strong")
	insertBufferEvent(p2Func2, 40, "g_counter", "race_condition")
	insertGuardEvent(p2Func2, 39, "TRUTH_CHECK", "strong")
	insertBufferEvent(p2Func3, 29, "malloc", "memory_leak")
	insertGuardEvent(p2Func3, 28, "TRUTH_CHECK", "strong")

	insertBufferEvent(p3Func, 40, "system", "command_injection")
	insertGuardEvent(p3Func, 39, "TRUTH_CHECK", "weak")
	insertBufferEvent(p3Func2, 60, "g_account_balance", "race_condition")
	insertGuardEvent(p3Func2, 55, "NULL_CHECK", "weak")

	insertBufferEvent(tpFunc, 62, "memcpy", "buffer_overflow")
	insertBufferEvent(tpFunc2, 53, "sprintf", "sql_injection")

	for _, fid := range []int64{p0Func, p0Func2, p0Func3, p1Func, p1Func2, p2Func, p2Func2, p2Func3, p3Func, p3Func2, tpFunc, tpFunc2} {
		node, _ := s.GetOrCreateGraphNode(ctx, "function", fid, "")
		entryNode, _ := s.GetOrCreateGraphNode(ctx, "function", 0, `{"entry":true}`)
		s.InsertGraphEdge(ctx, &db.GraphEdge{SrcID: entryNode, DstID: node, EdgeType: "CALL"})
	}
}

func TestBenchmark_ConvergencePipeline(t *testing.T) {
	ctx := context.Background()
	s := newMockStore()
	setupBenchmarkData(s)

	allEvents, _ := s.ListEventsByType(ctx, "BUFFER_ACCESS")
	totalPotential := len(allEvents)
	if totalPotential != 18 {
		t.Errorf("expected 18 potential findings (BUFFER_ACCESS events), got %d", totalPotential)
	}

	safeFilter := NewSafeFunctionFilter(s)
	afterSafe, err := safeFilter.Apply(ctx, toCandidates(allEvents, s, ctx))
	if err != nil {
		t.Fatalf("safe function filter failed: %v", err)
	}
	if len(afterSafe) != 8 {
		t.Errorf("after safe function filter: expected 8 (18-7 P0-3 P1), got %d", len(afterSafe))
	}

	boundsFilter := NewBoundsCheckFilter(s)
	afterBounds, err := boundsFilter.Apply(ctx, afterSafe)
	if err != nil {
		t.Fatalf("bounds check filter failed: %v", err)
	}
	if len(afterBounds) != 4 {
		t.Errorf("after bounds check filter: expected 4 (2 TP confirmed + 2 P3 suspected), got %d", len(afterBounds))
	}

	suspectedCount := 0
	confirmedCount := 0
	for _, c := range afterBounds {
		if c.SuspicionLevel == "suspected" {
			suspectedCount++
		} else {
			confirmedCount++
		}
	}
	if suspectedCount != 2 {
		t.Errorf("expected 2 suspected (P3 edge cases), got %d", suspectedCount)
	}
	if confirmedCount != 2 {
		t.Errorf("expected 2 confirmed (TP true positives), got %d", confirmedCount)
	}

	t.Logf("Convergence: 18 → safe_filter → 8 → bounds_check → 4 (2 TP confirmed + 2 P3 suspected)")
	t.Logf("P3 edge cases retained with suspicion_level='suspected' for AI agent court review.")
}

func TestBenchmark_P3SuspectedRetention(t *testing.T) {
	ctx := context.Background()
	s := newMockStore()
	setupBenchmarkData(s)

	allEvents, _ := s.ListEventsByType(ctx, "BUFFER_ACCESS")
	candidates := toCandidates(allEvents, s, ctx)

	safeFilter := NewSafeFunctionFilter(s)
	afterSafe, _ := safeFilter.Apply(ctx, candidates)

	boundsFilter := NewBoundsCheckFilter(s)
	afterBounds, _ := boundsFilter.Apply(ctx, afterSafe)

	p3Func, _ := s.GetFunctionByName(ctx, "run_admin_command")
	p3Func2, _ := s.GetFunctionByName(ctx, "check_and_transfer")
	p3FuncID := int64(0)
	p3Func2ID := int64(0)
	if p3Func != nil {
		p3FuncID = p3Func.ID
	}
	if p3Func2 != nil {
		p3Func2ID = p3Func2.ID
	}

	for _, c := range afterBounds {
		if c.FunctionID == p3FuncID || c.FunctionID == p3Func2ID {
			if c.GuardStrength != "weak" {
				t.Errorf("P3 candidate %s: expected guard_strength='weak', got %q", c.FunctionName, c.GuardStrength)
			}
			if c.SuspicionLevel != "suspected" {
				t.Errorf("P3 candidate %s: expected suspicion_level='suspected', got %q", c.FunctionName, c.SuspicionLevel)
			}
			if !c.IsGuarded {
				t.Errorf("P3 candidate %s: expected is_guarded=true", c.FunctionName)
			}
		}
	}

	for _, c := range afterBounds {
		if c.FunctionID != p3FuncID && c.FunctionID != p3Func2ID {
			if c.SuspicionLevel == "suspected" {
				t.Errorf("non-P3 candidate %s should not be suspected", c.FunctionName)
			}
		}
	}
}

func TestBenchmark_EvidenceItemSuspicionLevel(t *testing.T) {
	ctx := context.Background()
	s := newMockStore()
	setupBenchmarkData(s)

	allEvents, _ := s.ListEventsByType(ctx, "BUFFER_ACCESS")
	candidates := toCandidates(allEvents, s, ctx)

	safeFilter := NewSafeFunctionFilter(s)
	afterSafe, _ := safeFilter.Apply(ctx, candidates)

	boundsFilter := NewBoundsCheckFilter(s)
	afterBounds, _ := boundsFilter.Apply(ctx, afterSafe)

	for _, c := range afterBounds {
		spec, _ := GetVulnTypeSpec("buffer-overflow")
		item := newEvidenceItem(c, spec, "")
		if c.SuspicionLevel == "suspected" {
			if item.SuspicionLevel != "suspected" {
				t.Errorf("evidence item for %s: expected suspicion_level='suspected'", c.FunctionName)
			}
			hasWeakGuard := false
			for _, frag := range item.Evidence {
				if frag.Type == "weak_guard" {
					hasWeakGuard = true
				}
			}
			if !hasWeakGuard {
				t.Errorf("evidence item for %s: expected weak_guard evidence fragment", c.FunctionName)
			}
		} else {
			if item.SuspicionLevel != "suspected" {
				t.Errorf("evidence item for %s: expected suspicion_level='suspected' for buffer-overflow, got %q", c.FunctionName, item.SuspicionLevel)
			}
		}
	}
}

func TestBenchmark_StrongGuardDismissal(t *testing.T) {
	ctx := context.Background()
	s := newMockStore()
	setupBenchmarkData(s)

	allEvents, _ := s.ListEventsByType(ctx, "BUFFER_ACCESS")
	candidates := toCandidates(allEvents, s, ctx)

	safeFilter := NewSafeFunctionFilter(s)
	afterSafe, _ := safeFilter.Apply(ctx, candidates)

	boundsFilter := NewBoundsCheckFilter(s)
	afterBounds, _ := boundsFilter.Apply(ctx, afterSafe)

	p2Func, _ := s.GetFunctionByName(ctx, "copy_message")
	p2Func2, _ := s.GetFunctionByName(ctx, "increment_counter")
	p2Func3, _ := s.GetFunctionByName(ctx, "process_buffer")

	p2FuncIDs := map[int64]bool{}
	if p2Func != nil {
		p2FuncIDs[p2Func.ID] = true
	}
	if p2Func2 != nil {
		p2FuncIDs[p2Func2.ID] = true
	}
	if p2Func3 != nil {
		p2FuncIDs[p2Func3.ID] = true
	}
	for _, c := range afterBounds {
		if p2FuncIDs[c.FunctionID] {
			t.Errorf("P2 candidate %s with strong guard should be dismissed, but was retained", c.FunctionName)
		}
	}
}

func TestBenchmark_PipelineByVulnType(t *testing.T) {
	ctx := context.Background()
	s := newMockStore()
	setupBenchmarkData(s)

	p := NewPlanner(s, nil, nil)
	result, err := p.Plan(ctx, "buffer-overflow")
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}

	if result.Summary.SeedCount != 18 {
		t.Errorf("expected 18 seeds, got %d", result.Summary.SeedCount)
	}

	if result.CandidateCount() > 30 {
		t.Errorf("candidates should be capped at 30, got %d", result.CandidateCount())
	}
}

func TestBenchmark_SafeFunctionFilter(t *testing.T) {
	ctx := context.Background()
	s := newMockStore()
	setupBenchmarkData(s)

	safeFuncs := []string{"memcpy_s", "strcpy_s", "sprintf_s", "strcat_s", "snprintf", "execve", "sqlite3_prepare_v2"}
	for _, name := range safeFuncs {
		c := Candidate{VariableName: name}
		result, err := NewSafeFunctionFilter(s).Apply(ctx, []Candidate{c})
		if err != nil {
			t.Fatalf("filter failed: %v", err)
		}
		if len(result) != 0 {
			t.Errorf("safe function %s should be excluded", name)
		}
	}

	safeWraps := []string{"SafeCopy_copy", "SafeCopy_strcpy", "SafeQuery_exec", "ResourceHandle_create", "LockGuard_create"}
	for _, name := range safeWraps {
		c := Candidate{FunctionName: name}
		result, err := NewSafeFunctionFilter(s).Apply(ctx, []Candidate{c})
		if err != nil {
			t.Fatalf("filter failed: %v", err)
		}
		if len(result) != 0 {
			t.Errorf("safe wrapper %s should be excluded", name)
		}
	}

	unsafeFuncs := []string{"memcpy", "strcpy", "sprintf", "system", "sqlite3_exec"}
	for _, name := range unsafeFuncs {
		c := Candidate{VariableName: name}
		result, err := NewSafeFunctionFilter(s).Apply(ctx, []Candidate{c})
		if err != nil {
			t.Fatalf("filter failed: %v", err)
		}
		if len(result) != 1 {
			t.Errorf("unsafe function %s should NOT be excluded", name)
		}
	}
}

func toCandidates(events []*db.SecurityEvent, s *mockStore, ctx context.Context) []Candidate {
	var candidates []Candidate
	for _, e := range events {
		var props struct {
			Function string `json:"function"`
			Variable string `json:"variable"`
		}
		json.Unmarshal([]byte(e.Properties), &props)
		name := props.Variable
		if name == "" {
			name = props.Function
		}
		candidates = append(candidates, Candidate{
			DerefEventID: e.ID,
			FunctionID:   e.EntityID,
			FunctionName: props.Function,
			VariableName: name,
			LocationID:   e.LocationID,
		})
	}
	return candidates
}
