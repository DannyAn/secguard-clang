package planner

import (
	"context"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// TestSeedPropsFlowToCandidate guards the props→Candidate field flow for the
// keys the second-round audit found silently dropped (R2-01~07): the detector
// emits them and eventProps decodes them, but the candidate loader never
// copied them, so the evidence file and hint rendered without a fact the
// detector had already proved. Each case feeds one seed event shaped exactly
// like the detector's emission and asserts the candidate carries the field.
func TestSeedPropsFlowToCandidate(t *testing.T) {
	cases := []struct {
		name     string
		vulnType string
		props    string
		check    func(t *testing.T, c Candidate)
	}{
		{
			name:     "race TOCTOU check/use/path_arg",
			vulnType: "race-condition",
			props:    `{"category":"toctou","check_function":"access","use_function":"fopen","path_arg":"path"}`,
			check: func(t *testing.T, c Candidate) {
				if c.CheckFunction != "access" || c.UseFunction != "fopen" || c.CheckPathArg != "path" {
					t.Errorf("TOCTOU fields lost: check=%q use=%q arg=%q", c.CheckFunction, c.UseFunction, c.CheckPathArg)
				}
			},
		},
		{
			name:     "race toctou_shared_state mutex and string-encoded lines",
			vulnType: "race-condition",
			props:    `{"category":"toctou_shared_state","mutex":"g_lock","lock_line":"140","unlock_line":"150"}`,
			check: func(t *testing.T, c Candidate) {
				if c.Mutex != "g_lock" {
					t.Errorf("mutex lost: %q", c.Mutex)
				}
				// The detector emits line numbers as STRINGS; a plain int
				// field decodes them to zero (the E-02 failure mode).
				if c.LockLine != 140 || c.UnlockLine != 150 {
					t.Errorf("lock/unlock lines lost: %d/%d", c.LockLine, c.UnlockLine)
				}
			},
		},
		{
			name:     "crypto reason and string-encoded key_size",
			vulnType: "crypto-misuse",
			props:    `{"category":"undersized_key","reason":"key size < 16 bytes (minimum 128-bit)","key_size":"8","function":"DES_set_key"}`,
			check: func(t *testing.T, c Candidate) {
				if c.CryptoReason == "" {
					t.Errorf("crypto reason lost: %q", c.CryptoReason)
				}
				if c.CryptoKeySize != 8 {
					t.Errorf("key size lost: %d", c.CryptoKeySize)
				}
			},
		},
		{
			name:     "format-string format_arg",
			vulnType: "format-string",
			props:    `{"format_arg":"user_fmt","expression":"printf(user_fmt)"}`,
			check: func(t *testing.T, c Candidate) {
				if c.FormatArg != "user_fmt" {
					t.Errorf("format_arg lost: %q", c.FormatArg)
				}
			},
		},
		{
			name:     "path-traversal path expression",
			vulnType: "path-traversal",
			props:    `{"path":"user_path","function":"fopen"}`,
			check: func(t *testing.T, c Candidate) {
				if c.PathExpr != "user_path" {
					t.Errorf("path expression lost: %q", c.PathExpr)
				}
			},
		},
		{
			name:     "memory-leak acquire api",
			vulnType: "memory-leak",
			props:    `{"variable":"p","origin":"malloc","api":"malloc"}`,
			check: func(t *testing.T, c Candidate) {
				if c.APIName != "malloc" {
					t.Errorf("allocation api lost: %q", c.APIName)
				}
			},
		},
		{
			name:     "resource-leak acquire api",
			vulnType: "resource-leak",
			props:    `{"variable":"f","origin":"resource_acquire","api":"fopen"}`,
			check: func(t *testing.T, c Candidate) {
				if c.APIName != "fopen" {
					t.Errorf("acquire api lost: %q", c.APIName)
				}
			},
		},
		{
			name:     "integer-overflow lhs_influenced",
			vulnType: "integer-overflow",
			props:    `{"category":"unsigned_sub_underflow","lhs_influenced":"true","expression":"a - b"}`,
			check: func(t *testing.T, c Candidate) {
				if !c.SubLHSInfluenced {
					t.Error("lhs_influenced lost")
				}
			},
		},
	}

	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newMockStore()
			fileID, _ := s.InsertFile(ctx, &db.File{Path: "flow.c", Language: "c", LOC: 10})
			fnID, _ := s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "fn", StartLine: 1, EndLine: 10})
			locID, _ := s.InsertLocation(ctx, &db.Location{FileID: fileID, Line: 3})
			spec, err := GetVulnTypeSpec(tc.vulnType)
			if err != nil {
				t.Fatalf("spec: %v", err)
			}
			s.InsertEvent(ctx, &db.SecurityEvent{
				EventType: spec.SeedEventType, EntityID: fnID, LocationID: locID,
				Properties: tc.props,
			})
			p := NewPlanner(s, nil, nil)
			cands, _, err := p.seedCandidatesByType(ctx, spec)
			if err != nil {
				t.Fatalf("seed: %v", err)
			}
			if len(cands) != 1 {
				t.Fatalf("expected 1 candidate, got %d", len(cands))
			}
			tc.check(t, cands[0])
		})
	}
}
