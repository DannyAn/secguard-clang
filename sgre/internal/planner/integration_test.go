package planner

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kongan/secguard-lite/internal/db"
)

func TestEndToEnd_FullWorkflow(t *testing.T) {
	s := newMockStore()
	ctx := context.Background()

	fileID, _ := s.InsertFile(ctx, &db.File{Path: "vulnerable.c", Language: "c", LOC: 15})

	getUser, _ := s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "get_user", StartLine: 1, EndLine: 5})
	foo, _ := s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "foo", StartLine: 6, EndLine: 15})

	loc1, _ := s.InsertLocation(ctx, &db.Location{FileID: fileID, Line: 2})
	loc2, _ := s.InsertLocation(ctx, &db.Location{FileID: fileID, Line: 10})

	s.InsertEvent(ctx, &db.SecurityEvent{
		EventType: "NULL_VALUE", EntityID: getUser, LocationID: loc1,
		Properties: `{"variable":"<return>","origin":"return"}`,
	})
	s.InsertEvent(ctx, &db.SecurityEvent{
		EventType: "NULL_VALUE", EntityID: foo, LocationID: loc2,
		Properties: `{"variable":"user","origin":"call_return"}`,
	})

	s.InsertEvent(ctx, &db.SecurityEvent{
		EventType: "DEREFERENCE", EntityID: foo, LocationID: loc2,
		Properties: `{"variable":"user","expression":"user->name"}`,
	})

	nodeGetUser, _ := s.GetOrCreateGraphNode(ctx, "function", getUser, "")
	nodeFoo, _ := s.GetOrCreateGraphNode(ctx, "function", foo, "")
	s.InsertGraphEdge(ctx, &db.GraphEdge{SrcID: nodeFoo, DstID: nodeGetUser, EdgeType: "CALL"})

	varSrc, _ := s.GetOrCreateGraphNode(ctx, "variable_ref", foo, `{"name":"user"}`)
	varDst, _ := s.GetOrCreateGraphNode(ctx, "variable_ref", foo, `{"name":"user_deref"}`)
	s.InsertGraphEdge(ctx, &db.GraphEdge{SrcID: varSrc, DstID: varDst, EdgeType: "DATA_FLOW"})

	p := NewPlanner(s, nil, nil)
	result, err := p.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}

	t.Logf("Pipeline: seed=%d -> filters=%v -> final=%d",
		result.Summary.SeedCount,
		filterStats(result.Summary.Filters),
		result.Summary.FinalCount)

	if result.Summary.SeedCount != 1 {
		t.Errorf("expected 1 seed candidate (1 dereference), got %d", result.Summary.SeedCount)
	}

	if result.Summary.FinalCount == 0 {
		t.Error("expected at least 1 final candidate (unguarded null dereference)")
	}

	for _, item := range result.Candidates {
		if item.Target.Function != "foo" {
			t.Errorf("expected target function 'foo', got %q", item.Target.Function)
		}
		if item.Target.Variable != "user" {
			t.Errorf("expected target variable 'user', got %q", item.Target.Variable)
		}
	}

	findingID, err := s.InsertFinding(ctx, &db.Finding{
		RuleID:     "NULL_DEREFERENCE",
		Severity:   "high",
		Confidence: 0.95,
		Evidence:   `{"target":"foo:10","variable":"user"}`,
		Status:     "open",
	})
	if err != nil {
		t.Fatalf("InsertFinding failed: %v", err)
	}
	if findingID == 0 {
		t.Error("expected non-zero finding ID")
	}

	findings, _ := s.ListFindings(ctx)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "NULL_DEREFERENCE" {
		t.Errorf("expected rule_id NULL_DEREFERENCE, got %q", findings[0].RuleID)
	}

	data, _ := result.ToJSON()
	var jsonResult map[string]interface{}
	json.Unmarshal(data, &jsonResult)
	if jsonResult["vulnerability_type"] != "null-deref" {
		t.Error("JSON output missing vulnerability_type")
	}

	t.Logf("End-to-end workflow: index -> plan -> finding -> report: PASS")
}

func filterStats(filters []FilterStats) string {
	result := ""
	for i, f := range filters {
		if i > 0 {
			result += " -> "
		}
		result += f.Name + "(" + itoa(f.InputCount) + "->" + itoa(f.OutputCount) + ")"
	}
	return result
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
