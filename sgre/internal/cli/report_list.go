package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
	"github.com/DannyAn/secguard-clang/internal/report"
)

// runReportListAutoConfirmed handles `report --list-auto-confirmed`.
//
// --list-auto-confirmed emits the machine auto-confirmed findings as a JSON
// list for the AI agent to RE-REVIEW. This is the agent-native second-round
// review: the agent (not an external HTTP provider) applies its skill rules
// to each entry and writes verdicts back via `--review-json` (confirmed |
// dismissed), which maps a `dismissed` to a suppressed finding in result.sarif.
// Each entry carries the exact source statement (snippet) so the agent can
// judge the machine verdict without a per-finding source READ.
func runReportListAutoConfirmed(ctx context.Context, store db.Store, remaining []string) int {
	scanID := parseStringFlag(remaining, "scan-id")
	if scanID == "" {
		scanID, _ = store.GetLatestScanID(ctx)
	}
	// --type <kebab,...> scopes the list to one type's CWE set, so a subagent
	// re-reviews ONLY its own type's machine findings.
	var ruleIDs []string
	if typeFilter := parseStringFlag(remaining, "type"); typeFilter != "" {
		var types []string
		for _, vt := range strings.Split(typeFilter, ",") {
			if vt = strings.TrimSpace(vt); vt != "" {
				types = append(types, vt)
			}
		}
		var rerr error
		ruleIDs, rerr = planner.VulnTypesToRuleIDs(types)
		if rerr != nil {
			WriteErrorJSON(fmt.Sprintf("invalid --type filter: %v", rerr))
			return 1
		}
	}
	// --limit <n> bounds the batch so a large auto-confirmed set is pulled in
	// pages instead of overflowing the agent's context in one tool return.
	limit := parseIntFlag(remaining, "limit")
	if limit < 0 {
		limit = 0
	}
	findings, err := store.ListAutoConfirmedForReview(ctx, scanID, ruleIDs, limit)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to list auto-confirmed findings: %v", err))
		return 1
	}
	cwd, _ := os.Getwd()
	out := make([]map[string]interface{}, 0, len(findings))
	for _, f := range findings {
		entry := map[string]interface{}{
			"id":      f.ID,
			"rule_id": f.RuleID,
			// vuln_type lets a Step 5.5 re-reviewer settle each row against the
			// RIGHT machine-proof premise (and its per-type count) without
			// reverse-mapping rule_id→type by hand — a multi-CWE type
			// (divide-by-zero's int_min_div → CWE-190) made that hand-mapping
			// wrong and burned the whole review turn re-deriving it.
			"vuln_type": f.VulnType,
			"file":      f.FilePath,
			"line":      f.LineNumber,
			"function":  f.FunctionName,
			"variable":  f.Variable,
			"summary":   f.Summary,
			"reasoning": f.Reasoning,
			"snippet":   report.SourceLineText(f.FilePath, f.LineNumber, cwd),
			// context is the ±reviewContextLines window around the finding.
			// The false-positive judgment this listing feeds ("the result IS
			// checked", "the buffer is never used") needs the statement's
			// neighbours; a single-line snippet forced one source READ per
			// re-review, which is exactly the cost the snippet exists to
			// remove. Kept beside snippet (not replacing it) so a consumer
			// that only needs the statement still gets one line.
			"context": report.SourceWindowText(f.FilePath, f.LineNumber, reviewContextLines, cwd),
		}
		// hint/facts carry the SAME distilled basis the initial
		// classification saw (Evidence Contract v2): the pipeline's hint
		// token sequence and the structured verdict facts persisted at
		// auto-confirm time. A re-reviewer holding only snippet+context
		// re-derived what the pipeline already knew — the round3 "getter
		// mistaken for an allocator" dismissals came exactly from there.
		hint, facts := autoConfirmBasis(f.Properties)
		if hint != "" {
			entry["hint"] = hint
		}
		if len(facts) > 0 {
			entry["facts"] = facts
		}
		out = append(out, entry)
	}
	_ = WriteJSON(map[string]interface{}{"findings": out, "count": len(out)})
	return 0
}

// runReportList handles `report --list`, the read-all-findings mode.
func runReportList(ctx context.Context, store db.Store, remaining []string) int {
	statusFilter := parseStringFlag(remaining, "status")
	scanID := parseStringFlag(remaining, "scan-id")

	var findings []*db.Finding
	var err error
	if scanID != "" {
		findings, err = store.ListFindingsByScanID(ctx, scanID)
	} else {
		findings, err = store.ListFindings(ctx)
	}
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to list findings: %v", err))
		return 1
	}
	// Filter by the post-A5 effective verdict, not the raw first-pass status, so
	// a reviewed finding is listed under its final verdict (consistent with the
	// audit report, SARIF, and suppression index).
	if statusFilter != "" {
		filtered := make([]*db.Finding, 0, len(findings))
		for _, f := range findings {
			if f.EffectiveStatus() == statusFilter {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	type listItem struct {
		*db.Finding
		// VulnType and Variable shadow the embedded Finding fields so the output
		// schema is FIXED: vuln_type comes from the finding's own attribution
		// (not re-derived from rule_id), and variable is always present ("" when
		// absent) so a consumer never hits a KeyError (P2-12).
		VulnType string `json:"vuln_type"`
		Variable string `json:"variable"`
		// EffectiveStatus is the post-review binary verdict the --status filter
		// matched on, so a row whose raw status is still auto-confirmed but whose
		// review_status=dismissed does not mislead a consumer into reading it as a
		// machine-confirmed defect.
		EffectiveStatus string `json:"effective_status"`
	}
	items := make([]listItem, 0, len(findings))
	for _, f := range findings {
		vt := f.VulnType
		if vt == "" {
			vt = planner.TypeForCWE(f.RuleID)
		}
		items = append(items, listItem{Finding: f, VulnType: vt, Variable: f.Variable, EffectiveStatus: f.EffectiveStatus()})
	}
	// Stable envelope regardless of whether the list is empty: the bare-array
	// shape a non-empty result used to emit broke consumers that read
	// {"count":N,"findings":[...]} when empty (and vice-versa).
	out := map[string]interface{}{
		"count":    len(items),
		"findings": items,
	}
	if len(items) == 0 {
		out["message"] = "no findings in database; run 'secguard report --write ...' to persist findings after classifying candidates"
	}
	_ = WriteJSON(out)
	return 0
}
