package planner

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// setupBenchmarkData builds a mock store with 18 BUFFER_ACCESS events across
// the P0 (safe API), P1 (safe wrapper), P2 (bounds-checked), P3 (weak guard)
// and TP (true positive) benchmark tiers.
//
// Bounds-check suppression (P2) happens at the detector level — the
// buffer-overflow detector's hasPrecedingBoundsCheck simply does not emit a
// BUFFER_ACCESS event for a guarded call — so the planner's buffer-overflow
// chain is call_reach + safe_function_exclude only. The P2/P3 tiers are
// therefore modelled here as ordinary BUFFER_ACCESS events that pass through
// the planner (the detector would already have suppressed the real P2 case).
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
	insertBufferEvent(p2Func, 41, "memcpy", "buffer_overflow")
	insertBufferEvent(p2Func2, 40, "g_counter", "race_condition")
	insertBufferEvent(p2Func3, 29, "malloc", "memory_leak")

	insertBufferEvent(p3Func, 40, "system", "command_injection")
	insertBufferEvent(p3Func2, 60, "g_account_balance", "race_condition")

	insertBufferEvent(tpFunc, 62, "memcpy", "buffer_overflow")
	insertBufferEvent(tpFunc2, 53, "sprintf", "sql_injection")

	for _, fid := range []int64{p0Func, p0Func2, p0Func3, p1Func, p1Func2, p2Func, p2Func2, p2Func3, p3Func, p3Func2, tpFunc, tpFunc2} {
		node, _ := s.GetOrCreateGraphNode(ctx, "function", fid, "")
		entryNode, _ := s.GetOrCreateGraphNode(ctx, "function", 0, `{"entry":true}`)
		s.InsertGraphEdge(ctx, &db.GraphEdge{SrcID: entryNode, DstID: node, EdgeType: "CALL"})
	}
}

// TestBenchmark_ConvergencePipeline verifies the buffer-overflow chain:
// 18 seeds → safe_function_exclude drops P0 (7 safe APIs) + P1 (3 safe
// wrappers) → 8 remain (P2/P3/TP pass through to the AI agent for review).
func TestBenchmark_ConvergencePipeline(t *testing.T) {
	ctx := context.Background()
	s := newMockStore()
	setupBenchmarkData(s)

	allEvents, _ := s.ListEventsByType(ctx, "BUFFER_ACCESS")
	if len(allEvents) != 18 {
		t.Errorf("expected 18 BUFFER_ACCESS events, got %d", len(allEvents))
	}

	safeFilter := NewSafeFunctionFilter(s)
	afterSafe, _, err := safeFilter.Apply(ctx, toCandidates(allEvents, s, ctx))
	if err != nil {
		t.Fatalf("safe function filter failed: %v", err)
	}
	if len(afterSafe) != 8 {
		t.Errorf("after safe function filter: expected 8 (18 - 7 P0 - 3 P1), got %d", len(afterSafe))
	}
}

// TestBenchmark_SafeFunctionFilter verifies safe API and safe-wrapper exclusion.
func TestBenchmark_SafeFunctionFilter(t *testing.T) {
	ctx := context.Background()
	s := newMockStore()
	setupBenchmarkData(s)

	safeFuncs := []string{"memcpy_s", "strcpy_s", "sprintf_s", "strcat_s", "snprintf", "execve", "sqlite3_prepare_v2"}
	for _, name := range safeFuncs {
		c := Candidate{VariableName: name}
		result, _, err := NewSafeFunctionFilter(s).Apply(ctx, []Candidate{c})
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
		result, _, err := NewSafeFunctionFilter(s).Apply(ctx, []Candidate{c})
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
		result, _, err := NewSafeFunctionFilter(s).Apply(ctx, []Candidate{c})
		if err != nil {
			t.Fatalf("filter failed: %v", err)
		}
		if len(result) != 1 {
			t.Errorf("unsafe function %s should NOT be excluded", name)
		}
	}
}

// TestBenchmark_PipelineByVulnType verifies the end-to-end Plan for
// buffer-overflow: 18 seeds converge (dedup + rank + cap) without exceeding
// the candidate cap.
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
