package aireview

import (
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/config"
	"github.com/DannyAn/secguard-clang/internal/review"
)

func newTestReviewer() *HTTPReviewer {
	return &HTTPReviewer{
		endpoint:      "http://localhost:8080/v1/chat/completions",
		apiKey:        "test-key",
		model:         "test-model",
		timeoutMs:     5000,
		maxRetries:    0,
		promptVersion: "1",
		schemaVersion: "1",
	}
}

func TestParseAndValidate_ValidAIConfirmed(t *testing.T) {
	r := newTestReviewer()
	raw := `{"finding_id":42,"verdict":"ai_confirmed","rationale":"confirmed","supporting_evidence":["ev1"],"confidence":0.9}`
	payload := &review.ReviewPayload{Finding: review.FindingMeta{FindingID: 42}}
	v, err := r.parseAndValidate(raw, payload)
	if err != nil {
		t.Fatalf("parseAndValidate: %v", err)
	}
	if v.Verdict != review.VerdictAIConfirmed {
		t.Errorf("Verdict = %q, want ai_confirmed", v.Verdict)
	}
}

func TestParseAndValidate_ValidFalsePositive(t *testing.T) {
	r := newTestReviewer()
	raw := `{"finding_id":1,"verdict":"false_positive","rationale":"not a bug","contradicting_evidence":["guard exists"],"confidence":0.8}`
	payload := &review.ReviewPayload{Finding: review.FindingMeta{FindingID: 1}}
	v, err := r.parseAndValidate(raw, payload)
	if err != nil {
		t.Fatalf("parseAndValidate: %v", err)
	}
	if v.Verdict != review.VerdictFalsePositive {
		t.Errorf("Verdict = %q, want false_positive", v.Verdict)
	}
}

func TestParseAndValidate_UnknownVerdict(t *testing.T) {
	r := newTestReviewer()
	raw := `{"finding_id":1,"verdict":"maybe","rationale":"unsure"}`
	payload := &review.ReviewPayload{Finding: review.FindingMeta{FindingID: 1}}
	_, err := r.parseAndValidate(raw, payload)
	if err == nil {
		t.Fatal("expected error for unknown verdict")
	}
}

func TestParseAndValidate_FindingIDMismatch(t *testing.T) {
	r := newTestReviewer()
	raw := `{"finding_id":99,"verdict":"ai_confirmed","supporting_evidence":["ev"]}`
	payload := &review.ReviewPayload{Finding: review.FindingMeta{FindingID: 1}}
	_, err := r.parseAndValidate(raw, payload)
	if err == nil {
		t.Fatal("expected error for finding_id mismatch")
	}
}

func TestParseAndValidate_FalsePositiveNoEvidence(t *testing.T) {
	r := newTestReviewer()
	raw := `{"finding_id":1,"verdict":"false_positive","rationale":"not a bug"}`
	payload := &review.ReviewPayload{Finding: review.FindingMeta{FindingID: 1}}
	_, err := r.parseAndValidate(raw, payload)
	if err == nil {
		t.Fatal("expected error: false_positive requires contradicting_evidence")
	}
}

func TestParseAndValidate_AIConfirmedNoEvidence(t *testing.T) {
	r := newTestReviewer()
	raw := `{"finding_id":1,"verdict":"ai_confirmed","rationale":"confirmed"}`
	payload := &review.ReviewPayload{Finding: review.FindingMeta{FindingID: 1}}
	_, err := r.parseAndValidate(raw, payload)
	if err == nil {
		t.Fatal("expected error: ai_confirmed requires supporting_evidence")
	}
}

func TestParseAndValidate_NeedsMoreEvidenceNoEvidence(t *testing.T) {
	r := newTestReviewer()
	raw := `{"finding_id":1,"verdict":"needs_more_evidence","rationale":"unsure"}`
	payload := &review.ReviewPayload{Finding: review.FindingMeta{FindingID: 1}}
	_, err := r.parseAndValidate(raw, payload)
	if err == nil {
		t.Fatal("expected error: needs_more_evidence requires missing_evidence")
	}
}

func TestParseAndValidate_EmptyResponse(t *testing.T) {
	r := newTestReviewer()
	payload := &review.ReviewPayload{Finding: review.FindingMeta{FindingID: 1}}
	_, err := r.parseAndValidate("", payload)
	if err == nil {
		t.Fatal("expected error for empty response")
	}
}

func TestParseAndValidate_JSONWrappedInText(t *testing.T) {
	r := newTestReviewer()
	raw := `Here is the verdict: {"finding_id":1,"verdict":"ai_confirmed","supporting_evidence":["ev"],"confidence":0.9} hope this helps!`
	payload := &review.ReviewPayload{Finding: review.FindingMeta{FindingID: 1}}
	v, err := r.parseAndValidate(raw, payload)
	if err != nil {
		t.Fatalf("parseAndValidate with wrapped JSON: %v", err)
	}
	if v.Verdict != review.VerdictAIConfirmed {
		t.Errorf("Verdict = %q, want ai_confirmed", v.Verdict)
	}
}

func TestRenderPrompt_ContainsXMLTags(t *testing.T) {
	r := newTestReviewer()
	payload := &review.ReviewPayload{
		SchemaVersion: "1",
		Finding: review.FindingMeta{
			FindingID: 1,
			Detector:  "null-deref",
			Severity:  "high",
		},
		Source: review.SourceInfo{
			Revision:    "abc",
			CodeExcerpt: "int *p = 0;\nreturn *p;",
		},
		Evidence: review.EvidenceBundle{
			TriggerEvidence: []review.EvidenceFragment{
				{Type: "null_source", Role: "seed", Detail: "assigned 0"},
			},
		},
	}
	messages := r.renderPrompt(payload)
	if len(messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(messages))
	}
	if messages[0].Role != "system" {
		t.Errorf("first message role = %q, want system", messages[0].Role)
	}
	if messages[1].Role != "user" {
		t.Errorf("second message role = %q, want user", messages[1].Role)
	}
	userContent := messages[1].Content
	for _, tag := range []string{"<source_code>", "</source_code>", "<evidence>", "</evidence>"} {
		if !strings.Contains(userContent, tag) {
			t.Errorf("user message missing XML tag %q", tag)
		}
	}
}

func TestNewHTTPReviewer_Defaults(t *testing.T) {
	cfg := &config.AIReview{
		Provider:  "openai",
		Endpoint:  "http://localhost",
		TimeoutMs: 0,
	}
	r := NewHTTPReviewer(cfg)
	if r.timeoutMs != 30000 {
		t.Errorf("default timeoutMs = %d, want 30000", r.timeoutMs)
	}
	if r.maxRetries != 0 {
		t.Errorf("default maxRetries = %d, want 0", r.maxRetries)
	}
}
