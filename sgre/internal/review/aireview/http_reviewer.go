package aireview

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/DannyAn/secguard-clang/internal/config"
	"github.com/DannyAn/secguard-clang/internal/review"
)

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type HTTPReviewer struct {
	endpoint      string
	apiKey        string
	model         string
	timeoutMs     int
	maxRetries    int
	promptVersion string
	schemaVersion string
	client        *http.Client
}

func NewHTTPReviewer(cfg *config.AIReview) *HTTPReviewer {
	timeoutMs := cfg.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 30000
	}
	maxRetries := cfg.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}
	return &HTTPReviewer{
		endpoint:      cfg.Endpoint,
		apiKey:        resolveAPIKey(cfg.APIKeyEnv),
		model:         cfg.Model,
		timeoutMs:     timeoutMs,
		maxRetries:    maxRetries,
		promptVersion: cfg.PromptVersion,
		schemaVersion: cfg.SchemaVersion,
		client:        &http.Client{Timeout: time.Duration(timeoutMs) * time.Millisecond},
	}
}

func resolveAPIKey(envVar string) string {
	if envVar == "" {
		return ""
	}
	return os.Getenv(envVar)
}

func (r *HTTPReviewer) Review(ctx context.Context, payload *review.ReviewPayload) (*review.Verdict, error) {
	messages := r.renderPrompt(payload)
	var lastErr error
	backoff := time.Second
	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
		raw, err := r.callProvider(ctx, messages)
		if err != nil {
			lastErr = err
			continue
		}
		verdict, verr := r.parseAndValidate(raw, payload)
		if verr == nil {
			return verdict, nil
		}
		lastErr = verr
	}
	return nil, fmt.Errorf("aireview: review failed after %d attempts: %w", r.maxRetries+1, lastErr)
}

func (r *HTTPReviewer) renderPrompt(payload *review.ReviewPayload) []ChatMessage {
	system := `You are a security code reviewer. Analyze the finding and return a JSON verdict.
The verdict must be one of: "ai_confirmed", "false_positive", "needs_more_evidence".
Output ONLY valid JSON with this schema:
{
  "finding_id": <int>,
  "verdict": "<string>",
  "rationale": "<string>",
  "supporting_evidence": ["<string>"],
  "contradicting_evidence": ["<string>"],
  "missing_evidence": ["<string>"],
  "confidence": <float>
}
Rules:
- false_positive requires non-empty contradicting_evidence
- ai_confirmed requires non-empty supporting_evidence
- needs_more_evidence requires non-empty missing_evidence`

	var evidenceBuf strings.Builder
	for _, e := range payload.Evidence.TriggerEvidence {
		fmt.Fprintf(&evidenceBuf, "- type=%s role=%s detail=%s\n", e.Type, e.Role, e.Detail)
	}

	user := fmt.Sprintf(`Review finding %d (detector=%s, severity=%s).

<source_code>
%s
</source_code>

<evidence>
%s
</evidence>

Review requirements:
- Assumptions: %s
- Required evidence: %s
- Known limitations: %s`,
		payload.Finding.FindingID,
		payload.Finding.Detector,
		payload.Finding.Severity,
		payload.Source.CodeExcerpt,
		evidenceBuf.String(),
		strings.Join(payload.ReviewRequirements.RuleAssumptions, "; "),
		strings.Join(payload.ReviewRequirements.RequiredEvidence, "; "),
		strings.Join(payload.ReviewRequirements.KnownLimitations, "; "))

	return []ChatMessage{
		{Role: "system", Content: system},
		{Role: "user", Content: user},
	}
}

func (r *HTTPReviewer) callProvider(ctx context.Context, messages []ChatMessage) (string, error) {
	reqBody := map[string]interface{}{
		"model":    r.model,
		"messages": messages,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("aireview: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", r.endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("aireview: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if r.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+r.apiKey)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("aireview: http call: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("aireview: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("aireview: provider returned status %d: %s", resp.StatusCode, string(data))
	}
	var respObj struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &respObj); err != nil {
		return "", fmt.Errorf("aireview: parse response: %w", err)
	}
	if len(respObj.Choices) == 0 {
		return "", fmt.Errorf("aireview: provider returned no choices")
	}
	return respObj.Choices[0].Message.Content, nil
}

func (r *HTTPReviewer) parseAndValidate(raw string, payload *review.ReviewPayload) (*review.Verdict, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("aireview: empty verdict response")
	}
	if idx := strings.Index(raw, "{"); idx > 0 {
		raw = raw[idx:]
	}
	if idx := strings.LastIndex(raw, "}"); idx >= 0 && idx < len(raw)-1 {
		raw = raw[:idx+1]
	}
	var v review.Verdict
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return nil, fmt.Errorf("aireview: parse verdict JSON: %w", err)
	}
	switch v.Verdict {
	case review.VerdictAIConfirmed, review.VerdictFalsePositive, review.VerdictNeedsMoreEvidence:
	default:
		return nil, fmt.Errorf("aireview: invalid verdict %q (must be ai_confirmed/false_positive/needs_more_evidence)", v.Verdict)
	}
	if v.FindingID != payload.Finding.FindingID {
		return nil, fmt.Errorf("aireview: finding_id mismatch: verdict=%d payload=%d", v.FindingID, payload.Finding.FindingID)
	}
	switch v.Verdict {
	case review.VerdictFalsePositive:
		if len(v.ContradictingEvidence) == 0 {
			return nil, fmt.Errorf("aireview: false_positive requires non-empty contradicting_evidence")
		}
	case review.VerdictAIConfirmed:
		if len(v.SupportingEvidence) == 0 {
			return nil, fmt.Errorf("aireview: ai_confirmed requires non-empty supporting_evidence")
		}
	case review.VerdictNeedsMoreEvidence:
		if len(v.MissingEvidence) == 0 {
			return nil, fmt.Errorf("aireview: needs_more_evidence requires non-empty missing_evidence")
		}
	}
	return &v, nil
}
