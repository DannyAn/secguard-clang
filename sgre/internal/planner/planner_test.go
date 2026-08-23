package planner

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

func setupConvergenceTestData(s *mockStore) {
	fileID, _ := s.InsertFile(context.Background(), &db.File{Path: "test.c", Language: "c"})

	funcA, _ := s.InsertFunction(context.Background(), &db.Function{FileID: fileID, Name: "foo", StartLine: 1, EndLine: 20})
	funcB, _ := s.InsertFunction(context.Background(), &db.Function{FileID: fileID, Name: "bar", StartLine: 21, EndLine: 40})
	funcC, _ := s.InsertFunction(context.Background(), &db.Function{FileID: fileID, Name: "safe_func", StartLine: 41, EndLine: 60})

	loc1, _ := s.InsertLocation(context.Background(), &db.Location{FileID: fileID, Line: 10})
	loc2, _ := s.InsertLocation(context.Background(), &db.Location{FileID: fileID, Line: 30})
	loc3, _ := s.InsertLocation(context.Background(), &db.Location{FileID: fileID, Line: 50})

	s.InsertEvent(context.Background(), &db.SecurityEvent{EventType: "NULL_VALUE", EntityID: funcA, LocationID: loc1, Properties: `{"variable":"p","origin":"malloc"}`})
	s.InsertEvent(context.Background(), &db.SecurityEvent{EventType: "NULL_VALUE", EntityID: funcB, LocationID: loc2, Properties: `{"variable":"q","origin":"return"}`})

	s.InsertEvent(context.Background(), &db.SecurityEvent{EventType: "DEREFERENCE", EntityID: funcA, LocationID: loc1, Properties: `{"variable":"p","expression":"p->field"}`})
	s.InsertEvent(context.Background(), &db.SecurityEvent{EventType: "DEREFERENCE", EntityID: funcB, LocationID: loc2, Properties: `{"variable":"q","expression":"*q"}`})
	s.InsertEvent(context.Background(), &db.SecurityEvent{EventType: "DEREFERENCE", EntityID: funcC, LocationID: loc3, Properties: `{"variable":"r","expression":"r[0]"}`})

	s.InsertEvent(context.Background(), &db.SecurityEvent{EventType: "NULL_GUARD", EntityID: funcC, LocationID: loc3, Properties: `{"variable":"r","condition":"NULL_CHECK","scope_start":45,"scope_end":60}`})

	nodeA, _ := s.GetOrCreateGraphNode(context.Background(), "function", funcA, "")
	nodeB, _ := s.GetOrCreateGraphNode(context.Background(), "function", funcB, "")
	nodeC, _ := s.GetOrCreateGraphNode(context.Background(), "function", funcC, "")

	s.InsertGraphEdge(context.Background(), &db.GraphEdge{SrcID: nodeA, DstID: nodeB, EdgeType: "CALL"})
	s.InsertGraphEdge(context.Background(), &db.GraphEdge{SrcID: nodeB, DstID: nodeC, EdgeType: "CALL"})

	varNode1, _ := s.GetOrCreateGraphNode(context.Background(), "variable_ref", funcA, `{"name":"p"}`)
	varNode2, _ := s.GetOrCreateGraphNode(context.Background(), "variable_ref", funcB, `{"name":"q"}`)
	s.InsertGraphEdge(context.Background(), &db.GraphEdge{SrcID: varNode1, DstID: varNode2, EdgeType: "DATA_FLOW", Properties: `{"variable":"p"}`})
}

func TestPlan_EndToEnd_ConvergencePipeline(t *testing.T) {
	s := newMockStore()
	setupConvergenceTestData(s)

	p := NewPlanner(s, nil, nil)
	ctx := context.Background()

	result, err := p.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}

	if result.VulnerabilityType != "null-deref" {
		t.Errorf("expected vulnerability_type 'null-deref', got %q", result.VulnerabilityType)
	}

	if result.Summary.SeedCount != 3 {
		t.Errorf("expected seed count 3 (3 dereferences), got %d", result.Summary.SeedCount)
	}

	if len(result.Summary.Filters) != 7 {
		t.Errorf("expected 7 filter stats, got %d", len(result.Summary.Filters))
	}

	expectedFilters := []string{"sizeof_pseudo_deref", "non_nullable_array_suppress", "array_oob_precedence", "nullable_source", "call_reach", "guard", "safe_function_exclude"}
	for i, name := range expectedFilters {
		if i >= len(result.Summary.Filters) {
			t.Errorf("missing filter %s", name)
			continue
		}
		if result.Summary.Filters[i].Name != name {
			t.Errorf("filter %d: expected %s, got %s", i, name, result.Summary.Filters[i].Name)
		}
	}

	if result.Summary.Filters[0].InputCount != 3 {
		t.Errorf("Filter 0 input: expected 3, got %d", result.Summary.Filters[0].InputCount)
	}
	if result.Summary.Filters[0].OutputCount != 3 {
		t.Errorf("Filter 0 output: expected 3 (no sizeof pseudo-derefs in mock data), got %d", result.Summary.Filters[0].OutputCount)
	}
	if result.Summary.Filters[3].OutputCount != 2 {
		t.Errorf("Filter 3 output: expected 2 (funcA and funcB have NULL_VALUE, funcC does not), got %d", result.Summary.Filters[3].OutputCount)
	}
}

func TestPlan_EndToEnd_JSONOutput(t *testing.T) {
	s := newMockStore()
	setupConvergenceTestData(s)

	p := NewPlanner(s, nil, nil)
	ctx := context.Background()

	result, err := p.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}

	data, err := result.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("JSON output is not valid: %v", err)
	}

	if parsed["vulnerability_type"] != "null-deref" {
		t.Errorf("expected vulnerability_type 'null-deref', got %v", parsed["vulnerability_type"])
	}
}

func TestPlan_EndToEnd_Max30Candidates(t *testing.T) {
	s := newMockStore()
	fileID, _ := s.InsertFile(context.Background(), &db.File{Path: "test.c"})
	funcID, _ := s.InsertFunction(context.Background(), &db.Function{FileID: fileID, Name: "foo", StartLine: 1, EndLine: 200})

	s.InsertEvent(context.Background(), &db.SecurityEvent{EventType: "NULL_VALUE", EntityID: funcID, Properties: `{"variable":"p"}`})

	for i := 0; i < 40; i++ {
		loc, _ := s.InsertLocation(context.Background(), &db.Location{FileID: fileID, Line: i + 1})
		s.InsertEvent(context.Background(), &db.SecurityEvent{
			EventType:  "DEREFERENCE",
			EntityID:   funcID,
			LocationID: loc,
			Properties: `{"variable":"p","expression":"p->f"}`,
		})
	}

	p := NewPlanner(s, nil, nil)
	result, err := p.Plan(context.Background(), "null-deref")
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}

	if len(result.Candidates) > 30 {
		t.Errorf("expected at most 30 candidates, got %d", len(result.Candidates))
	}
}

func TestPlan_EndToEnd_ShortCircuit(t *testing.T) {
	s := newMockStore()
	fileID, _ := s.InsertFile(context.Background(), &db.File{Path: "test.c"})
	funcID, _ := s.InsertFunction(context.Background(), &db.Function{FileID: fileID, Name: "foo", StartLine: 1, EndLine: 10})

	loc, _ := s.InsertLocation(context.Background(), &db.Location{FileID: fileID, Line: 5})
	s.InsertEvent(context.Background(), &db.SecurityEvent{
		EventType:  "DEREFERENCE",
		EntityID:   funcID,
		LocationID: loc,
		Properties: `{"variable":"p","expression":"p->f"}`,
	})

	p := NewPlanner(s, nil, nil)
	result, err := p.Plan(context.Background(), "null-deref")
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}

	if !result.Summary.ShortCircuited {
		t.Error("expected short-circuit when Filter 1 produces 0 candidates (no NULL_VALUE events)")
	}
	if len(result.Candidates) != 0 {
		t.Errorf("expected 0 candidates after short-circuit, got %d", len(result.Candidates))
	}
}

func TestPlan_EndToEnd_UnsupportedVulnType(t *testing.T) {
	s := newMockStore()
	p := NewPlanner(s, nil, nil)

	_, err := p.Plan(context.Background(), "unsupported-type")
	if err == nil {
		t.Error("expected error for unsupported vulnerability type")
	}
}

func TestPlan_EndToEnd_FilterLogging(t *testing.T) {
	s := newMockStore()
	setupConvergenceTestData(s)

	p := NewPlanner(s, nil, nil)
	result, err := p.Plan(context.Background(), "null-deref")
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}

	for _, f := range result.Summary.Filters {
		if f.InputCount < 0 || f.OutputCount < 0 {
			t.Errorf("filter %s has negative counts: input=%d output=%d", f.Name, f.InputCount, f.OutputCount)
		}
		if f.OutputCount > f.InputCount {
			t.Errorf("filter %s output (%d) > input (%d)", f.Name, f.OutputCount, f.InputCount)
		}
	}
}

func TestPlan_EndToEnd_EvidenceItemStructure(t *testing.T) {
	s := newMockStore()
	setupConvergenceTestData(s)

	p := NewPlanner(s, nil, nil)
	result, err := p.Plan(context.Background(), "null-deref")
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}

	for _, item := range result.Candidates {
		if item.Type != "NULL_DEREFERENCE" {
			t.Errorf("expected type NULL_DEREFERENCE, got %s", item.Type)
		}
		if item.Target.Function == "" {
			t.Error("evidence item missing function name")
		}
		if item.Target.Variable == "" {
			t.Error("evidence item missing variable name")
		}
		if len(item.Evidence) == 0 {
			t.Error("evidence item has no evidence fragments")
		}
	}
}

func TestDeduplicateCandidates_ConvergeByVariable(t *testing.T) {
	// A single nullable variable dereferenced at many sites is one defect, so
	// null-deref (convergeByVariable=true) collapses it to one finding per
	// (function, variable), keeping the earliest dereference line.
	cands := []Candidate{
		{FileID: 1, FunctionName: "parse_packet", VariableName: "packet", Line: 45},
		{FileID: 1, FunctionName: "parse_packet", VariableName: "packet", Line: 51},
		{FileID: 1, FunctionName: "parse_packet", VariableName: "packet", Line: 62},
		{FileID: 1, FunctionName: "parse_packet", VariableName: "packet->data", Line: 56},
	}

	got := deduplicateCandidates(cands, &VulnTypeSpec{ConvergeByVariable: true})
	if len(got) != 2 {
		t.Fatalf("expected 2 converged candidates (packet, packet->data), got %d", len(got))
	}
	if got[0].VariableName != "packet" || got[0].Line != 45 {
		t.Errorf("expected first candidate packet@45, got %s@%d", got[0].VariableName, got[0].Line)
	}
	if got[1].VariableName != "packet->data" {
		t.Errorf("expected second candidate packet->data, got %s", got[1].VariableName)
	}

	// Without convergence each dereference line is a distinct candidate.
	if gotAll := deduplicateCandidates(cands, &VulnTypeSpec{}); len(gotAll) != 4 {
		t.Errorf("expected 4 candidates without convergence, got %d", len(gotAll))
	}
}

func TestPlan_CategorySplit_BufferAccess(t *testing.T) {
	ctx := context.Background()
	s := newMockStore()
	fileID, _ := s.InsertFile(ctx, &db.File{Path: "t.c", Language: "c"})
	fid, _ := s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "oob", StartLine: 1, EndLine: 20})
	loc1, _ := s.InsertLocation(ctx, &db.Location{FileID: fileID, Line: 5})
	loc2, _ := s.InsertLocation(ctx, &db.Location{FileID: fileID, Line: 6})
	s.InsertEvent(ctx, &db.SecurityEvent{EventType: "BUFFER_ACCESS", EntityID: fid, LocationID: loc1, Properties: `{"category":"array_oob_read","expression":"arr[i]"}`})
	s.InsertEvent(ctx, &db.SecurityEvent{EventType: "BUFFER_ACCESS", EntityID: fid, LocationID: loc2, Properties: `{"category":"array_oob_write","expression":"buf[i]"}`})

	node, _ := s.GetOrCreateGraphNode(ctx, "function", fid, "")
	entry, _ := s.GetOrCreateGraphNode(ctx, "function", 0, `{"entry":true}`)
	s.InsertGraphEdge(ctx, &db.GraphEdge{SrcID: entry, DstID: node, EdgeType: "CALL"})

	p := NewPlanner(s, nil, nil)

	readResult, err := p.Plan(ctx, "out-of-bounds")
	if err != nil {
		t.Fatalf("Plan(out-of-bounds) failed: %v", err)
	}
	if readResult.Summary.SeedCount != 1 || readResult.CandidateCount() != 1 {
		t.Errorf("out-of-bounds should seed only the array_oob_read event, got seeds=%d candidates=%d",
			readResult.Summary.SeedCount, readResult.CandidateCount())
	}

	writeResult, err := p.Plan(ctx, "buffer-overflow")
	if err != nil {
		t.Fatalf("Plan(buffer-overflow) failed: %v", err)
	}
	if writeResult.Summary.SeedCount != 1 || writeResult.CandidateCount() != 1 {
		t.Errorf("buffer-overflow should seed only the array_oob_write event, got seeds=%d candidates=%d",
			writeResult.Summary.SeedCount, writeResult.CandidateCount())
	}
}

func TestPlan_UncheckedReturn_UsesReturnCheckFilter(t *testing.T) {
	store := newMockStore()
	pl := NewPlanner(store, nil, nil)
	filters := pl.getFilters("unchecked-return")

	found := false
	for _, f := range filters {
		if f.Name() == "return_check" {
			found = true
			break
		}
	}
	if !found {
		names := make([]string, len(filters))
		for i, f := range filters {
			names[i] = f.Name()
		}
		t.Errorf("getFilters(unchecked-return) should include return_check filter, got %v", names)
	}
}
