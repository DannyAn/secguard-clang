package worker

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/planner"
)

const (
	defaultSkillMaxBytes     = 12000
	defaultCandidateMaxBytes = 3000
)

// Batch is one worker assignment: a vuln type plus a candidate range (0-based
// [RangeStart, RangeEnd) over the type's converged candidate list). It is the
// B-0 task-table unit, so the assembler is fed a slice already cut to the range.
type Batch struct {
	Type       string
	RangeStart int
	RangeEnd   int
	Candidates []planner.EvidenceItem
}

// CandidateIdentity is the conservation-audit key: the deterministic set of
// candidates a worker was assigned, so the executor can reconcile verdicts
// returned vs candidates expected without trusting the LLM's self-reported count.
type CandidateIdentity struct {
	Seq      int    `json:"seq"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Function string `json:"function"`
	Variable string `json:"variable"`
}

// Prompt is the self-contained, zero-tool worker prompt for one batch: the
// preloaded facts + skill + forced JSON output contract. The worker never opens
// a file — every fact it needs is already here.
type Prompt struct {
	Type           string              `json:"type"`
	Range          string              `json:"range"`
	Text           string              `json:"text"`
	Expected       []CandidateIdentity `json:"expected"`
	CandidateCount int                 `json:"candidate_count"`
}

// Options tune the prompt assembly. Zero values select the deterministic
// defaults, so the empty struct is always valid.
type Options struct {
	SkillText         string
	SkillMaxBytes     int
	CandidateMaxBytes int
}

// Assemble renders a deterministic worker prompt from a batch and its skill
// text. It performs no I/O and no LLM calls — it only expands the facts the
// pipeline already computed into prompt form.
func Assemble(b Batch, o Options) Prompt {
	skillMax := o.SkillMaxBytes
	if skillMax <= 0 {
		skillMax = defaultSkillMaxBytes
	}
	candMax := o.CandidateMaxBytes
	if candMax <= 0 {
		candMax = defaultCandidateMaxBytes
	}

	start, end := b.RangeStart, b.RangeEnd
	if start < 0 {
		start = 0
	}
	if end > len(b.Candidates) {
		end = len(b.Candidates)
	}
	if start > end {
		start = end
	}
	slice := b.Candidates[start:end]

	var sb strings.Builder
	fmt.Fprintf(&sb, "# worker batch: %s #%d-%d (%d candidates)\n", b.Type, start+1, end, len(slice))
	if o.SkillText != "" {
		sb.WriteString("\n## skill\n\n")
		sb.WriteString(truncateRunes(o.SkillText, skillMax))
		sb.WriteString("\n")
	}
	if legend := legendFor(slice); len(legend) > 0 {
		sb.WriteString("\n## hint legend\n\n")
		for _, l := range legend {
			sb.WriteString(l)
			sb.WriteString("\n")
		}
	}
	sb.WriteString("\n## candidates\n\n")
	expected := make([]CandidateIdentity, 0, len(slice))
	for i, c := range slice {
		seq := start + i + 1
		expected = append(expected, CandidateIdentity{
			Seq:      seq,
			File:     c.Target.File,
			Line:     c.Target.Line,
			Function: c.Target.Function,
			Variable: c.Target.Variable,
		})
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(renderCandidate(seq, c, candMax))
	}
	sb.WriteString("\n## output contract\n\n")
	sb.WriteString(outputContract())

	rng := "empty"
	if len(slice) > 0 {
		rng = fmt.Sprintf("%d-%d", start+1, end)
	}
	return Prompt{
		Type:           b.Type,
		Range:          rng,
		Text:           sb.String(),
		Expected:       expected,
		CandidateCount: len(slice),
	}
}

func legendFor(cands []planner.EvidenceItem) []string {
	seen := make(map[string]bool)
	var tokens []string
	for _, c := range cands {
		for _, t := range c.HintTokens {
			if !seen[t] {
				seen[t] = true
				tokens = append(tokens, t)
			}
		}
	}
	sort.Strings(tokens)
	return planner.HintLegendForTokens(tokens)
}

func renderCandidate(seq int, c planner.EvidenceItem, maxBytes int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "### #%d %s (%s:%d) %s (%s)\n",
		seq, c.Target.Function, filepath.Base(c.Target.File), c.Target.Line, c.Target.Variable, c.SuspicionLevel)
	if c.Signature != "" {
		fmt.Fprintf(&b, "- signature: `%s`\n", c.Signature)
	}
	if c.Expression != "" {
		fmt.Fprintf(&b, "- source: `%s`\n", c.Expression)
	}
	fmt.Fprintf(&b, "- hint: `%s`\n", c.Hint)
	if len(c.VerdictFacts) > 0 {
		b.WriteString("- verdict facts:\n")
		for _, vf := range c.VerdictFacts {
			fmt.Fprintf(&b, "  - `%s`: %s\n", vf.Token, vf.Detail)
		}
	}
	if len(c.Evidence) > 0 {
		b.WriteString("- evidence:\n")
		for _, e := range c.Evidence {
			label := e.Role
			if label == "" {
				label = e.Type
			}
			fmt.Fprintf(&b, "  - %s: %s\n", label, e.Detail)
		}
	}
	return truncateRunes(b.String(), maxBytes)
}

func outputContract() string {
	return "Return a JSON array of verdicts, exactly one object per candidate `#` above, with fields:\n" +
		"{\"seq\": <int>, \"status\": \"confirmed|dismissed|inconclusive\", \"cwe\": \"<CWE>\", \"reason\": \"<one-line citation>\"}\n" +
		"Every candidate MUST appear once; use status \"inconclusive\" when the preloaded facts cannot settle it (the executor escalates those batches)."
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "\n…[truncated]"
}
