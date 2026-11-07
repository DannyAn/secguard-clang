package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
	"github.com/DannyAn/secguard-clang/internal/report"
)

// reviewContextLines is the ± window embedded as `context` in the
// --list-auto-confirmed listing. It matches the candidate evidence window (±8):
// big enough to show a guard/return that settles a machine finding, small enough
// that a 50-entry page stays a cheap table review.
const reviewContextLines = 8

// autoConfirmBasis decodes the hint token sequence and the structured verdict
// facts persisted in a finding's properties at auto-confirm time (see
// buildAutoConfirmProperties in scan.go). Findings written before Evidence
// Contract v2 carry only the evidence fragments — both returns are empty and
// the re-review listing falls back to snippet+context, exactly the old
// behaviour.
func autoConfirmBasis(properties string) (hint string, facts []map[string]string) {
	if properties == "" {
		return "", nil
	}
	var parsed struct {
		HintTokens   []string `json:"auto_confirm_hint_tokens"`
		VerdictFacts []struct {
			Token  string `json:"Token"`
			Detail string `json:"Detail"`
		} `json:"auto_confirm_verdict_facts"`
	}
	if err := json.Unmarshal([]byte(properties), &parsed); err != nil {
		return "", nil
	}
	hint = strings.Join(parsed.HintTokens, " ")
	for _, vf := range parsed.VerdictFacts {
		if vf.Token != "" {
			facts = append(facts, map[string]string{"token": vf.Token, "detail": vf.Detail})
		}
	}
	return hint, facts
}

// normalizeAIVerdict maps a raw agent-supplied status to the BINARY AI verdict:
// confirmed (a real defect) or dismissed (everything else, including
// "undecidable"). There is no third state: if the AI cannot prove a defect, it
// is not a defect for the user, so a legacy `suspected` / `suspected-kept`
// spelling is coerced to `dismissed` (the reasoning is preserved, so the
// undecidable signal still lands in the DB as a dismissal record — the
// algorithm-improvement input — without ever reaching the user). `false-positive`
// is the skill file's spelling of `dismissed`. Any other value — including the
// pipeline intermediate state `open` — is rejected.
func normalizeAIVerdict(raw string) (string, error) {
	status := strings.ToLower(strings.TrimSpace(raw))
	switch status {
	case "confirmed":
		return status, nil
	case "dismissed", "false-positive", "false_positive", "false positive":
		return "dismissed", nil
	case "suspected", "suspected-kept":
		return "dismissed", nil
	default:
		return "", fmt.Errorf("invalid status %q — expected confirmed|dismissed", raw)
	}
}

// flexibleFloat accepts a JSON number OR a numeric string for a float field, so a
// worker that emits `"confidence":"55"` (string) instead of `55` is still parsed
// instead of failing the whole batch on an unmarshal type mismatch.
type flexibleFloat float64

func (f *flexibleFloat) UnmarshalJSON(data []byte) error {
	var num float64
	if err := json.Unmarshal(data, &num); err == nil {
		*f = flexibleFloat(num)
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("confidence must be a number or numeric string: %s", string(data))
	}
	num, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return fmt.Errorf("confidence must be numeric: %q", s)
	}
	*f = flexibleFloat(num)
	return nil
}

func parseStringFlag(args []string, flag string) string {
	prefix := "--" + flag + "="
	flagName := "--" + flag
	for i, a := range args {
		if strings.HasPrefix(a, prefix) {
			return a[len(prefix):]
		}
		if a == flagName && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// rejectConcatenatedArgs fails a command whose argv contains an element that
// looks like flags pre-joined into one string with a leading space, e.g.
// " --type path-traversal". Bun.$ template interpolation does not word-split, so
// an MCP tool that builds ` --type ${x}` and interpolates it as one element
// silently drops the flag — parseStringFlag matches `--type` or `--type=` only,
// and the leading-space element matches neither. Fail loudly instead of
// degrading to an unfiltered full dump.
func rejectConcatenatedArgs(args []string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, " ") && strings.Contains(a, " --") {
			WriteErrorJSON(fmt.Sprintf("argument %q looks like concatenated flags — pass each flag as a separate argument (e.g. --type path-traversal, not \" --type path-traversal\")", a))
			return false
		}
	}
	return true
}

// classifyWriteErr categorizes a finding-write error for the failed_details
// report: "write-busy" for SQLITE_BUSY/retry-exhaustion (the multi-subagent
// concurrent write storm), "write-error" for everything else. The class lands
// in the --write-json JSON output so the orchestrator can mark a type as
// missing due to contention vs a real data error.
func classifyWriteErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if strings.Contains(s, "busy retry exhausted") ||
		strings.Contains(s, "database is locked") ||
		strings.Contains(s, "SQLITE_BUSY") {
		return "write-busy"
	}
	return "write-error"
}

func parseFloatFlag(args []string, flag string) float64 {
	s := parseStringFlag(args, flag)
	if s == "" {
		return 0
	}
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

func parseIntFlag(args []string, flag string) int {
	s := parseStringFlag(args, flag)
	if s == "" {
		return 0
	}
	v, _ := strconv.Atoi(s)
	return v
}

func hasFlag(args []string, flag string) bool {
	prefix := "--" + flag + "="
	flagName := "--" + flag
	for _, a := range args {
		if a == flagName || strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}

func removeFlag(args []string, flag string) []string {
	flagName := "--" + flag
	prefix := flagName + "="
	result := []string{}
	skipNext := false
	for _, a := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if a == flagName {
			skipNext = true
			continue
		}
		if strings.HasPrefix(a, prefix) {
			continue
		}
		result = append(result, a)
	}
	return result
}

// parseExcludeFlag extracts a comma-separated `--exclude` directory list.
// present reports whether the flag was given at all; when it is, dirs is the
// (possibly empty) parsed list and the caller overrides the default excludes.
func parseExcludeFlag(args []string) (dirs []string, present bool) {
	for i, a := range args {
		if a == "--exclude" {
			if i+1 < len(args) {
				return splitComma(args[i+1]), true
			}
			return []string{}, true
		}
		if strings.HasPrefix(a, "--exclude=") {
			return splitComma(strings.TrimPrefix(a, "--exclude=")), true
		}
	}
	return nil, false
}

func splitComma(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// resolveFindingFilePath maps an agent-supplied `file` (absolute, repo-relative,
// or a truncated tail the agent copied out of report.md's shortFile column) back
// to the canonical absolute path stored in the files table. The suffix fallback
// is best-effort: when nothing resolves the input is returned unchanged, so a
// finding whose source cannot be located degrades to "no code context" in the
// SARIF/xlsx instead of being silently rewritten to a wrong path.
//
// files is the pre-fetched indexed file list; pass it to amortize ListFiles
// across a whole --write-json batch. When nil, it is fetched lazily (fine for a
// single --write call).
func resolveFindingFilePath(ctx context.Context, store db.Store, file string, files []*db.File) string {
	if file == "" || filepath.IsAbs(file) {
		return file
	}
	if files == nil {
		files, _ = store.ListFiles(ctx)
	}
	needle := string(filepath.Separator) + filepath.Clean(file)
	var best string
	for _, f := range files {
		if f.Path == file || strings.HasSuffix(f.Path, needle) {
			if best == "" || len(f.Path) < len(best) {
				best = f.Path
			}
		}
	}
	if best != "" {
		return best
	}
	return file
}

// dedupeAndNormalizeFindings normalizes every finding's file path to the indexed
// absolute path, then collapses rows that differ only by path spelling (absolute
// vs the truncated/relative tail the agent copied out of report.md). That
// double-write artifact made result.sarif list one vulnerability type twice
// (once per path spelling), because the idempotency key includes file_path.
// Keeping the first row per canonical (scan_id, rule_id, abs path, line,
// function) restores one finding per location.
func dedupeAndNormalizeFindings(ctx context.Context, store db.Store, findings []*db.Finding) []*db.Finding {
	if len(findings) == 0 {
		return findings
	}
	files, _ := store.ListFiles(ctx)
	seen := make(map[string]bool, len(findings))
	out := make([]*db.Finding, 0, len(findings))
	for _, f := range findings {
		f.FilePath = resolveFindingFilePath(ctx, store, f.FilePath, files)
		key := f.ScanID + "\x00" + f.RuleID + "\x00" + f.FilePath + "\x00" + strconv.Itoa(f.LineNumber) + "\x00" + f.FunctionName + "\x00" + f.Variable
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

func runReportCmd(ctx context.Context, args []string) int {
	dbPath, dbExplicit, remaining := parseDBFlag(args)
	if !rejectConcatenatedArgs(remaining) {
		return 1
	}

	dbPath, found := resolveExistingDBPath(dbExplicit, dbPath)
	if !found {
		WriteErrorJSON("no sgre.db found; run 'secguard scan <path>' first")
		return 1
	}

	store, err := openStore(ctx, dbPath)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to open database: %v", err))
		return 1
	}
	defer store.Close()

	// --list-auto-confirmed emits the machine auto-confirmed findings as a JSON
	// list for the AI agent to RE-REVIEW. This is the agent-native second-round
	// review: the agent (not an external HTTP provider) applies its skill rules
	// to each entry and writes verdicts back via `--review-json` (confirmed |
	// dismissed), which maps a `dismissed` to a suppressed finding in result.sarif.
	// Each entry carries the exact source statement (snippet) so the agent can
	// judge the machine verdict without a per-finding source READ.
	if hasFlag(remaining, "list-auto-confirmed") {
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
				"id":        f.ID,
				"rule_id":   f.RuleID,
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

	if hasFlag(remaining, "write") {
		confidence := parseFloatFlag(remaining, "confidence")
		if confidence > 1.0 {
			confidence = confidence / 100.0
		}
		// Clamp to the DB's [0,1] CHECK range so an out-of-range confidence
		// (e.g. 150) cannot fail InsertFinding with an opaque constraint error.
		if confidence > 1.0 {
			confidence = 1.0
		}
		if confidence < 0 {
			confidence = 0
		}

		finding := &db.Finding{
			RuleID:         parseStringFlag(remaining, "rule-id"),
			VulnType:       parseStringFlag(remaining, "vuln-type"),
			Severity:       parseStringFlag(remaining, "severity"),
			Confidence:     confidence,
			Evidence:       parseStringFlag(remaining, "evidence"),
			Status:         parseStringFlag(remaining, "status"),
			FilePath:       parseStringFlag(remaining, "file"),
			LineNumber:     parseIntFlag(remaining, "line"),
			FunctionName:   parseStringFlag(remaining, "function"),
			Variable:       parseStringFlag(remaining, "variable"),
			Properties:     parseStringFlag(remaining, "properties"),
			Summary:        parseStringFlag(remaining, "summary"),
			Reasoning:      parseStringFlag(remaining, "reasoning"),
			FixStrategy:    parseStringFlag(remaining, "fix-strategy"),
			ExceptionCheck: parseStringFlag(remaining, "exception-check"),
			ScanID:         parseStringFlag(remaining, "scan-id"),
		}
		// The agent tool carries structured output (summary/reasoning/
		// fix_strategy/exception_check) inside the --properties JSON, since a
		// JSON string is single-line (newlines escaped) and survives argument
		// passing regardless of the shell. Fall back to those keys when the
		// dedicated flags are absent, so multi-line reasoning/fix code is not lost.
		finding.ApplyStructuredFromProperties()
		// The properties JSON was only the transport; the structured fields now
		// live in their dedicated columns. Drop the raw copy so the DB stays lean.
		finding.Properties = ""
		if finding.Severity == "" {
			finding.Severity = "info"
		} else {
			finding.Severity = strings.ToLower(finding.Severity)
		}
		// The single --write path enforces the SAME verdict whitelist as the
		// batch --write-json path, so an AI can never persist the pipeline
		// intermediate state `open` (or an empty status) as a finding.
		if status, serr := normalizeAIVerdict(finding.Status); serr != nil {
			WriteErrorJSON(serr.Error())
			return 1
		} else {
			finding.Status = status
		}

		cweNorm := strings.ToUpper(strings.TrimSpace(finding.RuleID))
		if cweNorm == "" {
			WriteErrorJSON("--write requires a non-empty --rule-id (CWE)")
			return 1
		}
		if !db.SupportedFindingCWEs[cweNorm] {
			WriteErrorJSON(fmt.Sprintf("unsupported rule_id %q: SecGuard pipeline does not detect this vulnerability type. Supported CWEs: %s. Agent-observed findings for unsupported types should be reported as observations, not persisted.", finding.RuleID, db.SupportedCWEsList()))
			return 1
		}

		// Validate scan_id exists so findings can never be silently attached to
		// a nonexistent scan (e.g. a stale or typo'd id from the agent). An
		// empty scan_id is allowed for backward compatibility with callers that
		// don't track scans, but we first try to inherit the current scan from
		// the `latest` pointer: without a scan the per-finding markdown has no
		// directory to live in, and losing it silently is exactly the failure
		// that left dismissed candidates sitting in findings/.
		scanIDSource := "explicit"
		if finding.ScanID == "" {
			scanIDSource = "none"
			if cwd, err := os.Getwd(); err == nil && cwd != "" {
				if latest := report.LatestScanID(cwd); latest != "" {
					if stats, serr := store.ListScanStats(ctx, latest); serr == nil && len(stats) > 0 {
						finding.ScanID = latest
						scanIDSource = "latest"
					}
				}
			}
		}
		if finding.ScanID != "" {
			stats, err := store.ListScanStats(ctx, finding.ScanID)
			if err != nil {
				WriteErrorJSON(fmt.Sprintf("failed to validate scan_id: %v", err))
				return 1
			}
			if len(stats) == 0 {
				WriteErrorJSON(fmt.Sprintf("unknown scan_id %q: no scan_stats found for this id. Run 'secguard scan' first, or pass the scan_id from the scan output.", finding.ScanID))
				return 1
			}
		}

		// Normalize a relative/truncated agent-supplied file path to the indexed
		// absolute path, so the verdict markdown, result.sarif and result.xlsx can
		// all re-locate the source instead of emitting "Unable to find <file>".
		finding.FilePath = resolveFindingFilePath(ctx, store, finding.FilePath, nil)

		// Content-addressed identity for cross-scan dedup (incremental review).
		// Computed from the resolved absolute path (matching the --write-json
		// batch path) so the fingerprint is stable across path spellings.
		finding.Fingerprint = computeFingerprint(finding.RuleID, finding.FilePath, finding.FunctionName, finding.LineNumber)

		// A dismissed verdict writes no findings row, but it MUST land in the
		// candidate_verdicts ledger exactly like the batch --write-json path:
		// otherwise the sequential path's dismissals are invisible to recovery
		// ("classified and dismissed" vs "never classified").
		if finding.Status == "dismissed" {
			dismissedType := finding.VulnType
			if dismissedType == "" {
				dismissedType = planner.TypeForCWE(finding.RuleID)
			}
			dismissedWritten := false
			if dismissedType != "" && finding.ScanID != "" {
				if _, verr := store.UpsertCandidateVerdict(ctx, &db.CandidateVerdict{
					ScanID:       finding.ScanID,
					VulnType:     dismissedType,
					RuleID:       strings.ToUpper(strings.TrimSpace(finding.RuleID)),
					FilePath:     finding.FilePath,
					LineNumber:   finding.LineNumber,
					FunctionName: finding.FunctionName,
					Variable:     finding.Variable,
					Verdict:      "dismissed",
					Reason:       finding.Reasoning,
				}); verr != nil {
					WriteErrorJSON(fmt.Sprintf("failed to record dismissed verdict in candidate_verdicts: %v", verr))
					return 1
				}
				dismissedWritten = true
			}
			oc := syncPerFindingAfterWrite(remaining, finding)
			out := map[string]interface{}{
				"status":             "ok",
				"dismissed":          true,
				"dismissed_written":  dismissedWritten,
				"scan_id":            finding.ScanID,
				"scan_id_source":     scanIDSource,
				"per_finding_path":   oc.Path,
				"per_finding_action": oc.Action,
			}
			if oc.Warning != "" {
				out["per_finding_warning"] = oc.Warning
				fmt.Fprintf(os.Stderr, "warning: %s\n", oc.Warning)
			}
			WriteJSON(out)
			return 0
		}

		var id int64
		var duplicate bool
		// Probe and upsert in one IMMEDIATE transaction so the duplicate flag is
		// exact under concurrent writers: the second writer sees the first's row
		// and reports an idempotent update, never a silent second finding.
		if txErr := store.WithImmediateTx(ctx, func(tx db.Store) error {
			_, found, derr := tx.FindingIDByLocationKey(ctx, finding.ScanID, finding.RuleID, finding.FilePath, finding.LineNumber, finding.Variable)
			if derr != nil {
				return derr
			}
			duplicate = found
			var uerr error
			id, uerr = tx.UpsertFinding(ctx, finding)
			return uerr
		}); txErr != nil {
			WriteErrorJSON(fmt.Sprintf("failed to write finding: %v", txErr))
			return 1
		}
		if duplicate {
			fmt.Fprintf(os.Stderr, "duplicate: finding already exists at %s:%d — updated in place (idempotent write, not a second finding)\n", finding.FilePath, finding.LineNumber)
		}

		oc := syncPerFindingAfterWrite(remaining, finding)

		out := map[string]interface{}{
			"id":                 id,
			"status":             "ok",
			"duplicate":          duplicate,
			"scan_id":            finding.ScanID,
			"scan_id_source":     scanIDSource,
			"per_finding_path":   oc.Path,
			"per_finding_action": oc.Action,
		}
		if oc.Warning != "" {
			out["per_finding_warning"] = oc.Warning
			fmt.Fprintf(os.Stderr, "warning: %s\n", oc.Warning)
		}
		WriteJSON(out)
		return 0
	}

	// --write-json <file> writes a whole batch of findings in ONE subprocess
	// call, idempotently (re-running updates, never duplicates). It is the CLI
	// path a Claude Code agent (no MCP secguard_report tool) uses instead of
	// generating a per-finding bash loop, which is slow and error-prone. The file
	// is a JSON array of objects with keys rule_id/severity/confidence/status/
	// file/line/function/summary/reasoning/exception_check/fix_strategy. `-` or a
	// missing value reads from stdin.
	if hasFlag(remaining, "write-json") {
		src := parseStringFlag(remaining, "write-json")
		var data []byte
		var err error
		if src == "" || src == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(src)
		}
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to read --write-json input: %v", err))
			return 1
		}

		inputs, embeddedScanID, salvaged, perr := parseWriteJSONInput(data)
		if perr != nil {
			WriteErrorJSON(fmt.Sprintf("failed to parse --write-json input: %v. %s", perr, writeJSONShapeHint))
			return 1
		}

		// An explicit --scan-id wins; otherwise honour a scan_id embedded in an
		// object envelope, so the tolerated wrapper is not merely accepted but
		// attached to the right scan.
		scanID := parseStringFlag(remaining, "scan-id")
		if scanID == "" {
			scanID = embeddedScanID
		}

		// Resolve and validate scan_id with the SAME rules as the single `--write`
		// path, so a batch can never be silently attached to a typo'd/nonexistent
		// scan (and an empty scan_id still inherits the current scan from `latest`
		// for backward compatibility). Without this, a wrong scan_id writes every
		// finding into a dead scan that the orchestrator's `--audit --scan-id`
		// never reads back — the same silent false-negative this check prevents in
		// the single-write path.
		if scanID == "" {
			if cwd, err := os.Getwd(); err == nil && cwd != "" {
				if latest := report.LatestScanID(cwd); latest != "" {
					if stats, serr := store.ListScanStats(ctx, latest); serr == nil && len(stats) > 0 {
						scanID = latest
					}
				}
			}
		}
		if scanID != "" {
			stats, err := store.ListScanStats(ctx, scanID)
			if err != nil {
				WriteErrorJSON(fmt.Sprintf("failed to validate scan_id: %v", err))
				return 1
			}
			if len(stats) == 0 {
				WriteErrorJSON(fmt.Sprintf("unknown scan_id %q: no scan_stats found for this id. Run 'secguard scan' first, or pass the scan_id from the scan output.", scanID))
				return 1
			}
		}

		written := make([]map[string]interface{}, 0, len(inputs))
		var errs []string
		var failedDetails []map[string]interface{}
		// Fetch the indexed file list once so path resolution for a large batch
		// (e.g. 255 null-deref findings) does not re-scan the files table per row.
		// A failure here would silently degrade path resolution to the raw
		// (relative/truncated) agent-supplied path, which then bypasses the
		// uq_finding_loc idempotency key's absolute-path normalization. Fail the
		// batch instead (writes are idempotent, so a re-run is safe).
		allFiles, listErr := store.ListFiles(ctx)
		if listErr != nil {
			WriteErrorJSON(fmt.Sprintf("failed to list files for path resolution: %v", listErr))
			return 1
		}

		// First pass (read-only): validate every row and resolve its path to the
		// indexed absolute path, so the write pass below is pure upserts.
		type pendingWrite struct {
			in *findingInput
			f  *db.Finding
		}
		pending := make([]*pendingWrite, 0, len(inputs))
		writtenFindings := []*db.Finding{}
		type dismissedWrite struct {
			verdict *db.CandidateVerdict
			file    string
			line    int
		}
		var dismissedPending []dismissedWrite
		skippedDismissed := 0
		for i := range inputs {
			in := &inputs[i]
			in.normalizeAliases()
			// A finding with no location cannot be keyed, written to findings/,
			// or reconciled — the scan's auto-confirm path explicitly refuses
			// one. Reject it here with the expected keys named instead of
			// persisting a file_path='' line=0 row and exiting 0.
			if strings.TrimSpace(in.File) == "" || in.Line <= 0 {
				errs = append(errs, fmt.Sprintf("entry %d: missing location — expected \"file\" (string) and \"line\" (positive integer); the DB column names file_path/line_number are accepted as aliases", i))
				continue
			}
			confidence := float64(in.Confidence)
			if confidence > 1.0 {
				confidence /= 100.0
			}
			if confidence > 1.0 {
				confidence = 1.0
			}
			if confidence < 0 {
				confidence = 0
			}
			severity := strings.ToLower(in.Severity)
			if severity == "" {
				severity = "info"
			}

			// 校验 status 只能是二元裁决；非法值（如 pipeline 中间态 open）立即
			// 拒绝整批，而非 partial 跳过导致静默丢失。技能文件里把误报写成
			// `false-positive`，这是 `dismissed` 的同义判定——归一化后落库，避免
			// 子代理照抄技能原文导致整批被拒。
			status, serr := normalizeAIVerdict(in.Status)
			if serr != nil {
				WriteErrorJSON(fmt.Sprintf("invalid status %q at %s:%d — expected confirmed|dismissed", in.Status, in.File, in.Line))
				return 1
			}
			if status == "dismissed" {
				skippedDismissed++
				// Dismissed candidates are not persisted as findings, but the
				// verdict MUST land in the candidate_verdicts ledger — in the SAME
				// immediate transaction as the confirmed rows below, never as a
				// best-effort autocommit whose failure still returned status:ok.
				// Without that ledger row, recovery cannot tell "classified and
				// dismissed" from "never classified".
				dismissedType := in.VulnType
				if dismissedType == "" {
					dismissedType = planner.TypeForCWE(in.RuleID)
				}
				if dismissedType != "" {
					dismissedPending = append(dismissedPending, dismissedWrite{
						verdict: &db.CandidateVerdict{
							ScanID:       scanID,
							VulnType:     dismissedType,
							RuleID:       strings.ToUpper(strings.TrimSpace(in.RuleID)),
							FilePath:     resolveFindingFilePath(ctx, store, in.File, allFiles),
							LineNumber:   in.Line,
							FunctionName: in.Function,
							Variable:     in.Variable,
							Verdict:      "dismissed",
							Reason:       in.Reasoning,
						},
						file: in.File,
						line: in.Line,
					})
				}
				if scanDir := resolveScanDir(remaining, scanID); scanDir != "" {
					if dismissedType != "" {
						if _, serr := report.SyncPerFinding(scanDir, dismissedType, in.File, in.Line, report.PerFindingUpdate{
							Status:       "dismissed",
							Reasoning:    in.Reasoning,
							FunctionName: in.Function,
							Variable:     in.Variable,
							CWE:          in.RuleID,
						}); serr != nil {
							fmt.Fprintf(os.Stderr, "warning: annotate dismissed candidate %s:%d: %v\n", in.File, in.Line, serr)
						}
					}
				}
				continue
			}

			cweNorm := strings.ToUpper(strings.TrimSpace(in.RuleID))
			if cweNorm == "" {
				errs = append(errs, fmt.Sprintf("%s:%d — empty rule_id", in.File, in.Line))
				continue
			}
			if !db.SupportedFindingCWEs[cweNorm] {
				errs = append(errs, fmt.Sprintf("%s:%d — unsupported rule_id %q", in.File, in.Line, in.RuleID))
				continue
			}

			vt := in.VulnType
			if vt == "" {
				vt = planner.TypeForCWE(in.RuleID)
			}
			f := &db.Finding{
				RuleID:         cweNorm,
				VulnType:       vt,
				Severity:       severity,
				Confidence:     confidence,
				Status:         status,
				FilePath:       in.File,
				LineNumber:     in.Line,
				FunctionName:   in.Function,
				Variable:       in.Variable,
				Summary:        in.Summary,
				Reasoning:      in.Reasoning,
				FixStrategy:    in.FixStrategy,
				ExceptionCheck: in.ExceptionCheck,
				ScanID:         scanID,
			}
			f.FilePath = resolveFindingFilePath(ctx, store, f.FilePath, allFiles)
			f.Fingerprint = computeFingerprint(f.RuleID, f.FilePath, f.FunctionName, f.LineNumber)
			pending = append(pending, &pendingWrite{in: in, f: f})
		}

		// Second pass: write every finding in ONE transaction, so a large batch
		// commits once (one commit record + one write-lock acquisition) instead of
		// per-row autocommit (one implicit BEGIN/COMMIT + lock round-trip per row)
		// — the per-row autocommit was the write-side half of the null-deref
		// slowness. Use WithImmediateTx (BEGIN IMMEDIATE) rather than WithTx so
		// the write lock is acquired exactly ONCE up front: under the concurrent
		// subagent write storm a deferred transaction would re-wait busy_timeout
		// and the app-layer retry per row (~40s × N rows), which is what turned a
		// contended persist into a multi-minute/hang. BEGIN IMMEDIATE makes it
		// serialize fast or fail after one busy_timeout with a clean error.
		duplicates := 0
		dismissedWritten := 0
		dismissedFailed := 0
		if txErr := store.WithImmediateTx(ctx, func(tx db.Store) error {
			for _, p := range pending {
				duplicate := false
				if priorID, found, derr := tx.FindingIDByLocationKey(ctx, p.f.ScanID, p.f.RuleID, p.f.FilePath, p.f.LineNumber, p.f.Variable); derr != nil {
					errClass := classifyWriteErr(derr)
					errs = append(errs, fmt.Sprintf("%s:%d — duplicate probe: %v", p.in.File, p.in.Line, derr))
					failedDetails = append(failedDetails, map[string]interface{}{
						"file": p.in.File, "line": p.in.Line, "error_class": errClass, "message": derr.Error(),
					})
					fmt.Fprintf(os.Stderr, "FATAL: finding duplicate probe failed: %s:%d — [%s] %v\n", p.in.File, p.in.Line, errClass, derr)
					continue
				} else if found {
					duplicate = true
					duplicates++
					fmt.Fprintf(os.Stderr, "duplicate: finding already exists at %s:%d (id %d) — updated in place (idempotent write, not a second finding)\n", p.in.File, p.in.Line, priorID)
				}
				id, uerr := tx.UpsertFinding(ctx, p.f)
				if uerr != nil {
					errClass := classifyWriteErr(uerr)
					errs = append(errs, fmt.Sprintf("%s:%d — %v", p.in.File, p.in.Line, uerr))
					failedDetails = append(failedDetails, map[string]interface{}{
						"file": p.in.File, "line": p.in.Line, "error_class": errClass, "message": uerr.Error(),
					})
					fmt.Fprintf(os.Stderr, "FATAL: finding write failed: %s:%d — [%s] %v\n", p.in.File, p.in.Line, errClass, uerr)
					continue
				}
				written = append(written, map[string]interface{}{
					"file": p.in.File, "line": p.in.Line, "id": id, "duplicate": duplicate,
				})
				writtenFindings = append(writtenFindings, p.f)
			}
			for _, dw := range dismissedPending {
				if _, uerr := tx.UpsertCandidateVerdict(ctx, dw.verdict); uerr != nil {
					errClass := classifyWriteErr(uerr)
					errs = append(errs, fmt.Sprintf("dismissed verdict %s:%d — %v", dw.file, dw.line, uerr))
					failedDetails = append(failedDetails, map[string]interface{}{
						"file": dw.file, "line": dw.line, "error_class": errClass, "message": uerr.Error(),
					})
					fmt.Fprintf(os.Stderr, "FATAL: dismissed verdict write failed: %s:%d — [%s] %v\n", dw.file, dw.line, errClass, uerr)
					dismissedFailed++
					continue
				}
				dismissedWritten++
			}
			return nil
		}); txErr != nil {
			errClass := classifyWriteErr(txErr)
			errs = append(errs, fmt.Sprintf("batch commit — %v", txErr))
			failedDetails = append(failedDetails, map[string]interface{}{
				"error_class": errClass, "message": txErr.Error(),
			})
			fmt.Fprintf(os.Stderr, "FATAL: finding batch commit failed: [%s] %v\n", errClass, txErr)
		}

		// Mirror the single --write path: sync each persisted finding to its
		// per-finding markdown so findings/<type>/<file>.md never stays stale
		// relative to the DB after a batch write.
		for _, f := range writtenFindings {
			if oc := syncPerFindingAfterWrite(remaining, f); oc.Warning != "" {
				fmt.Fprintf(os.Stderr, "warning: %s\n", oc.Warning)
			}
		}

		out := map[string]interface{}{
			"status":            "ok",
			"findings_written":  len(written),
			"duplicates":        duplicates,
			"skipped_dismissed": skippedDismissed,
			"dismissed_written": dismissedWritten,
			"dismissed_failed":  dismissedFailed,
			"written":           written,
			"scan_id":           scanID,
			"failed_count":      len(errs),
		}
		if len(failedDetails) > 0 {
			out["failed_details"] = failedDetails
		}
		if salvaged {
			out["salvaged"] = true
			out["truncated"] = true
			out["salvaged_count"] = len(inputs)
			out["status"] = "partial"
			out["warning"] = "input JSON was truncated/invalid; only the complete leading findings were persisted — this batch is NOT a completion proof, re-write the full batch"
		}
		if len(errs) > 0 {
			out["status"] = "partial"
			out["errors"] = errs
		}
		WriteJSON(out)
		// A partial write is a failed write: exit non-zero so a CI gate keyed on
		// the exit code never mistakes dropped findings for success. errs (not
		// failedDetails) is the full set of dropped rows — it also covers the
		// validation skips (empty/unsupported rule_id) that `continue` before the
		// write pass, which failedDetails alone would miss.
		if len(errs) > 0 || salvaged {
			return 1
		}
		return 0
	}

	if hasFlag(remaining, "complete-type") {
		vulnType := parseStringFlag(remaining, "complete-type")
		scanID := parseStringFlag(remaining, "scan-id")
		if vulnType == "" {
			WriteErrorJSON("--complete-type requires a vulnerability type argument")
			return 1
		}
		if scanID == "" {
			WriteErrorJSON("--complete-type requires --scan-id")
			return 1
		}
		stats, err := store.ListScanStats(ctx, scanID)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to validate scan_id: %v", err))
			return 1
		}
		if len(stats) == 0 {
			WriteErrorJSON(fmt.Sprintf("unknown scan_id %q: no scan_stats found for this id", scanID))
			return 1
		}
		known := false
		for _, t := range planner.AllVulnTypes() {
			if t == vulnType {
				known = true
				break
			}
		}
		if !known {
			WriteErrorJSON(fmt.Sprintf("unsupported vuln_type %q: not a registered vulnerability type", vulnType))
			return 1
		}
		found := false
		for _, st := range stats {
			if st.VulnType == vulnType {
				found = true
				break
			}
		}
		if !found {
			WriteErrorJSON(fmt.Sprintf("no scan_stats for (scan_id=%q, vuln_type=%q)", scanID, vulnType))
			return 1
		}
		// Completion is PROVEN, not declared: when settlement rows exist for this
		// type, the done-range union must cover every candidate with no live
		// claim and no needs_context residue. One fast batch calling
		// --complete-type can no longer flip the whole type to done while other
		// ranges are still running, and this call never force-settles another
		// holder's in-flight claim. With no settlement rows at all (the
		// sequential orchestrator path writes no per-range settlements) the
		// orchestrator's explicit declaration is accepted as before.
		settlements, err := store.ListSettlementStatsByScan(ctx, scanID)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to load settlement rows: %v", err))
			return 1
		}
		var typeRows []*db.SettlementStat
		candidateCount := 0
		for _, st := range stats {
			if st.VulnType == vulnType {
				candidateCount = st.FinalCount
			}
		}
		for _, st := range settlements {
			if st.VulnType == vulnType {
				typeRows = append(typeRows, st)
			}
		}
		if len(typeRows) > 0 && candidateCount > 0 {
			cov := deriveTypeCoverage(typeRows, candidateCount, time.Now().Unix())
			if !cov.Done {
				WriteJSON(map[string]interface{}{
					"status":           "incomplete",
					"scan_id":          scanID,
					"vuln_type":        vulnType,
					"candidate_count":  candidateCount,
					"covered":          cov.CoveredCount,
					"uncovered_ranges": cov.Uncovered,
					"active_claims":    cov.ActiveClaims,
					"needs_context":    cov.HasNeedsContext,
					"error":            "type is not fully settled: re-dispatch the uncovered ranges and close live claims before --complete-type",
					"ai_stage_status":  "in-progress",
				})
				return 1
			}
		}
		if err := store.MarkAIStageDone(ctx, scanID, vulnType); err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to mark ai_stage_done: %v", err))
			return 1
		}
		WriteJSON(map[string]interface{}{
			"scan_id":         scanID,
			"vuln_type":       vulnType,
			"ai_stage_status": "done",
			"status":          "ok",
		})
		return 0
	}

	if hasFlag(remaining, "review") {
		findingID := int64(parseIntFlag(remaining, "id"))
		if findingID == 0 {
			WriteErrorJSON("--review requires --id=<finding_id>")
			return 1
		}
		reviewStatus := parseStringFlag(remaining, "review-status")
		reviewReasoning := parseStringFlag(remaining, "review-reasoning")
		switch reviewStatus {
		case "confirmed", "dismissed":
		default:
			WriteErrorJSON(fmt.Sprintf("invalid --review-status %q (expected confirmed|dismissed)", reviewStatus))
			return 1
		}

		f, err := store.GetFindingByID(ctx, findingID)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to load finding: %v", err))
			return 1
		}

		if err := store.UpdateFindingReview(ctx, findingID, reviewStatus, reviewReasoning); err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to update review: %v", err))
			return 1
		}

		finalStatus := reviewStatus
		// Re-send the structured content the first pass persisted, so the A5
		// review updates the verdict without wiping Summary/Reasoning/Fix
		// Strategy — and so a dismissal removes the file from findings/ rather
		// than leaving a confirmed-looking file behind.
		reviewed := *f
		reviewed.Status = finalStatus
		reviewed.ReviewStatus = ""
		oc := syncPerFindingAfterWrite(remaining, &reviewed)

		out := map[string]interface{}{
			"id":                 findingID,
			"review_status":      reviewStatus,
			"status":             "ok",
			"per_finding_path":   oc.Path,
			"per_finding_action": oc.Action,
		}
		if oc.Warning != "" {
			out["per_finding_warning"] = oc.Warning
			fmt.Fprintf(os.Stderr, "warning: %s\n", oc.Warning)
		}
		WriteJSON(out)
		return 0
	}

	// --review-json <file> records the A5 second-round verdicts for a WHOLE batch
	// of findings in ONE subprocess + ONE transaction, instead of the per-finding
	// `--review` loop that spawns a subprocess and opens SQLite per
	// row (the slow path that stretched a high-volume type like null-deref to
	// tens of minutes). Input is a JSON array of {id, review_status,
	// review_reasoning}. `-` or a missing value reads from stdin.
	if hasFlag(remaining, "review-json") {
		src := parseStringFlag(remaining, "review-json")
		var data []byte
		var err error
		if src == "" || src == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(src)
		}
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to read --review-json input: %v", err))
			return 1
		}

		type reviewInput struct {
			ID              int64  `json:"id"`
			ReviewStatus    string `json:"review_status"`
			ReviewReasoning string `json:"review_reasoning"`
		}
		var inputs []reviewInput
		if err := json.Unmarshal(data, &inputs); err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to parse --review-json array: %v", err))
			return 1
		}

		reviewed := make([]map[string]interface{}, 0, len(inputs))
		reviewedForSync := []reviewInput{}
		var errs []string
		// Pre-fetch the re-reviewable id set OUTSIDE the transaction: a deferred
		// WithTx built a read snapshot first and then upgraded to writes, which
		// returns SQLITE_BUSY_SNAPSHOT under concurrent writers (and the busy
		// handler does not retry that class). BEGIN IMMEDIATE takes the write
		// lock once, and the transaction body is now pure UPDATEs.
		allowed := map[int64]bool{}
		rows, qerr := store.DB().QueryContext(ctx, `SELECT id FROM findings WHERE status = 'auto-confirmed'`)
		if qerr != nil {
			WriteErrorJSON(fmt.Sprintf("failed to load auto-confirmed ids: %v", qerr))
			return 1
		}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				WriteErrorJSON(fmt.Sprintf("failed to scan auto-confirmed id: %v", err))
				return 1
			}
			allowed[id] = true
		}
		rows.Close()
		err = store.WithImmediateTx(ctx, func(tx db.Store) error {
			for i, in := range inputs {
				// A misspelled/omitted key decodes to the zero value, so name the
				// offending entry position and the expected keys instead of
				// reporting a bare `invalid review_status ""` — the caller
				// otherwise cannot tell a typo'd key from an invalid value.
				if in.ID == 0 {
					errs = append(errs, fmt.Sprintf("entry %d: missing required field \"id\" (expected {\"id\": <finding id>, \"review_status\": \"confirmed\"|\"dismissed\"})", i))
					continue
				}
				switch in.ReviewStatus {
				case "confirmed", "dismissed":
				default:
					if in.ReviewStatus == "" {
						errs = append(errs, fmt.Sprintf("entry %d (finding %d): missing required field \"review_status\" (expected \"confirmed\" or \"dismissed\"; a misspelled key decodes as empty)", i, in.ID))
					} else {
						errs = append(errs, fmt.Sprintf("entry %d (finding %d): invalid review_status %q (expected \"confirmed\" or \"dismissed\")", i, in.ID, in.ReviewStatus))
					}
					continue
				}
				// Only machine auto-confirmed findings are re-reviewable; a verdict
				// for any other finding id must not overwrite its status (RV-04).
				if !allowed[in.ID] {
					errs = append(errs, fmt.Sprintf("finding %d — not an auto-confirmed finding; re-review only applies to auto-confirmed findings", in.ID))
					continue
				}
				if uerr := tx.UpdateFindingReview(ctx, in.ID, in.ReviewStatus, in.ReviewReasoning); uerr != nil {
					errs = append(errs, fmt.Sprintf("finding %d — %v", in.ID, uerr))
					continue
				}
				reviewed = append(reviewed, map[string]interface{}{
					"id": in.ID, "review_status": in.ReviewStatus,
				})
				reviewedForSync = append(reviewedForSync, in)
			}
			return nil
		})
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to commit review batch: %v", err))
			return 1
		}

		// Mirror the single --review path: re-fetch each reviewed finding and
		// sync its per-finding markdown so a dismissal removes the file from
		// findings/ (and a confirmation writes it) after the batch commit.
		for _, in := range reviewedForSync {
			f, gerr := store.GetFindingByID(ctx, in.ID)
			if gerr != nil {
				fmt.Fprintf(os.Stderr, "warning: re-fetch reviewed finding %d: %v\n", in.ID, gerr)
				continue
			}
			rev := *f
			rev.Status = in.ReviewStatus
			rev.ReviewStatus = ""
			if oc := syncPerFindingAfterWrite(remaining, &rev); oc.Warning != "" {
				fmt.Fprintf(os.Stderr, "warning: %s\n", oc.Warning)
			}
		}

		out := map[string]interface{}{
			"status":       "ok",
			"reviewed":     reviewed,
			"review_count": len(reviewed),
		}
		if len(errs) > 0 {
			out["status"] = "partial"
			out["errors"] = errs
		}
		WriteJSON(out)
		// A partial review is a failed review: exit non-zero so the orchestrator
		// cannot misread a dropped verdict as "already persisted".
		if len(errs) > 0 {
			return 1
		}
		return 0
	}

	// --stats is the READ-ONLY per-type verdict census: confirmed / auto_confirmed
	// / dismissed / remaining in one query, with NO findings/ + SARIF + xlsx
	// re-render (P1-9). The orchestrator reads this instead of a second --audit.
	if hasFlag(remaining, "stats") {
		scanID := parseStringFlag(remaining, "scan-id")
		if scanID == "" {
			scanID, err = store.GetLatestScanID(ctx)
			if err != nil {
				WriteErrorJSON(fmt.Sprintf("failed to get latest scan_id: %v", err))
				return 1
			}
		}
		if scanID == "" {
			WriteErrorJSON("no scan stats found; run 'secguard scan' first")
			return 1
		}
		stats, err := store.ListScanStats(ctx, scanID)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to list scan stats: %v", err))
			return 1
		}
		verdictRows, err := store.DB().QueryContext(ctx,
			`SELECT vuln_type, status, COALESCE(review_status, ''), COUNT(*) FROM findings WHERE scan_id = ? GROUP BY vuln_type, status, review_status`,
			scanID)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to count verdicts by type: %v", err))
			return 1
		}
		dismissedByType, err := store.CountCandidateVerdictsByType(ctx, scanID)
		if err != nil {
			dismissedByType = map[string]int{}
		}
		type tally struct{ confirmed, auto int }
		byType := map[string]*tally{}
		for verdictRows.Next() {
			var vt, status, reviewStatus string
			var n int
			if err := verdictRows.Scan(&vt, &status, &reviewStatus, &n); err != nil {
				verdictRows.Close()
				WriteErrorJSON(fmt.Sprintf("failed to scan verdict tally: %v", err))
				return 1
			}
			if vt == "" {
				continue
			}
			if byType[vt] == nil {
				byType[vt] = &tally{}
			}
			// Mirror Finding.FinalStatus(): a review dismissal drops the row
			// from the confirmed set; an inconclusive review keeps first-pass.
			if reviewStatus == "dismissed" || reviewStatus == "suspected-kept" || reviewStatus == "false_positive" {
				continue
			}
			if status == db.StatusAutoConfirmed {
				byType[vt].auto += n
			} else if status == "confirmed" || reviewStatus == "confirmed" || reviewStatus == "ai_confirmed" {
				byType[vt].confirmed += n
			}
		}
		verdictRows.Close()
		rows := make([]map[string]interface{}, 0, len(stats))
		for _, st := range stats {
			t := byType[st.VulnType]
			confirmed, auto := 0, 0
			if t != nil {
				confirmed, auto = t.confirmed, t.auto
			}
			dismissed := dismissedByType[st.VulnType]
			// final_count counts needs-review candidates only (auto-confirmed
			// rows were never part of it) — subtracting auto here double-counted
			// the machine verdicts and could pin remaining at 0 prematurely.
			remaining := st.FinalCount - confirmed - dismissed
			if remaining < 0 {
				remaining = 0
			}
			rows = append(rows, map[string]interface{}{
				"vuln_type":       st.VulnType,
				"cwe":             planner.CWEForType(st.VulnType),
				"candidate_count": st.FinalCount,
				"confirmed":       confirmed,
				"auto_confirmed":  auto,
				"dismissed":       dismissed,
				"remaining":       remaining,
			})
		}
		WriteJSON(map[string]interface{}{"scan_id": scanID, "types": rows})
		return 0
	}

	if hasFlag(remaining, "audit") {
		scanID := parseStringFlag(remaining, "scan-id")
		if scanID == "" {
			scanID, err = store.GetLatestScanID(ctx)
			if err != nil {
				WriteErrorJSON(fmt.Sprintf("failed to get latest scan_id: %v", err))
				return 1
			}
		}
		if scanID == "" {
			WriteErrorJSON("no scan stats found; run 'secguard scan' first")
			return 1
		}

		// The AI-stage timing and the covered/in-flight ledger are derived from the
		// settlement reports the subagents write into .sgre/.tmp. The command
		// contract's happy path is `report --complete-type` + `report --audit`; it
		// need not (and in practice often does not) call `status --reports`.
		// Absorb the settlement files here too, so the audit self-measures the AI
		// stage and closes the pre-dispatch claims even when the orchestrator
		// skipped the explicit `status --reports` absorption step. Absorption is
		// idempotent, so a prior poll being re-run here is harmless.
		if res := listSubagentReports(dbPath, scanID); len(res.Reports) > 0 {
			if aerr := persistSettlementReports(ctx, store, res); aerr != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to absorb settlement reports for audit: %v\n", aerr)
			}
		}

		// AI-stage timing is now MEASURED by the engine from the settlement
		// reports' timestamps (`status --reports` persists each batch's finish
		// time). `--ai-duration-ms` is only an override for a host that cannot
		// write settlement files; supplying it wins over the self-measurement.
		var aiTiming aiStageTiming
		if settlements, lerr := store.ListSettlementStatsByScan(ctx, scanID); lerr == nil {
			aiTiming = measureAIStageTiming(settlements)
		}
		if raw := parseStringFlag(remaining, "ai-duration-ms"); raw != "" {
			ms, perr := strconv.ParseInt(raw, 10, 64)
			if perr != nil || ms < 0 {
				WriteErrorJSON(fmt.Sprintf("invalid --ai-duration-ms %q (expected a non-negative integer of milliseconds)", raw))
				return 1
			}
			// measured = wall-clock from a nanosecond timer; estimated = a
			// seconds-resolution approximation (P2-14). The source is persisted
			// so a production A/B never compares a measured number to a guess.
			source := parseStringFlag(remaining, "ai-duration-source")
			if source == "" {
				source = "measured"
			}
			if serr := store.SetScanRunAIDuration(ctx, scanID, ms, source); serr != nil {
				WriteErrorJSON(fmt.Sprintf("failed to record ai_duration_ms: %v", serr))
				return 1
			}
			aiTiming.TotalMS = ms
			aiTiming.Source = "override"
		} else if aiTiming.TotalMS > 0 {
			// Best-effort: a review/diff scan has no scan_runs row, and a missing
			// metrics row must not fail the audit. The timing is still rendered.
			if serr := store.SetScanRunAIDuration(ctx, scanID, aiTiming.TotalMS, "self-measured"); serr != nil {
				fmt.Fprintf(os.Stderr, "warning: could not record self-measured ai_duration_ms: %v\n", serr)
			}
		}

		stats, err := store.ListScanStats(ctx, scanID)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to list scan stats: %v", err))
			return 1
		}

		// Final-artifact gate: an audit must not present an unfinished AI stage
		// as a complete verdict set. Any type with candidates whose AI stage is
		// not done blocks the terminal artifacts unless the caller explicitly
		// asks for a partial report, in which case every artifact is labelled.
		allowPartial := hasFlag(remaining, "allow-partial")
		if !allowPartial {
			var unfinished []string
			for _, st := range stats {
				if st.FinalCount > 0 && st.AIStageStatus != "done" {
					unfinished = append(unfinished, fmt.Sprintf("%s(%s, candidates=%d)", st.VulnType, st.AIStageStatus, st.FinalCount))
				}
			}
			if len(unfinished) > 0 {
				WriteJSON(map[string]interface{}{
					"status":           "incomplete",
					"scan_id":          scanID,
					"unfinished_types": unfinished,
					"error":            "AI classification is not complete for these types; finish and settle them, or re-run with --allow-partial for an explicitly partial report",
				})
				return 1
			}
		}

		scanFindings, err := store.ListFindingsByScanID(ctx, scanID)
		if err != nil {
			// The audit report and result.sarif/result.xlsx are derived from these
			// findings; a read failure must not silently produce an empty report.
			WriteErrorJSON(fmt.Sprintf("failed to list findings for scan: %v", err))
			return 1
		}
		// Collapse duplicate rows that differ only by file-path spelling (the
		// absolute vs truncated double-write), and normalize paths to absolute so
		// every downstream report resolves source + embeds code context.
		scanFindings = dedupeAndNormalizeFindings(ctx, store, scanFindings)
		type vulnCounts struct {
			confirmed, suspected, autoConfirmed, reviewedOut int
		}
		countsByVuln := make(map[string]*vulnCounts)
		for _, f := range scanFindings {
			vt := f.VulnType
			if vt == "" {
				vt = planner.TypeForCWE(f.RuleID)
			}
			if vt == "" {
				continue
			}
			if countsByVuln[vt] == nil {
				countsByVuln[vt] = &vulnCounts{}
			}
			// Machine verdicts are counted apart from AI verdicts so the
			// audit-report can show both, and so the "candidates without AI
			// classification" remainder (final_count = needs-review candidates)
			// is not masked by the auto-confirmed rows.
			switch f.FinalStatus() {
			case "confirmed":
				if f.Status == db.StatusAutoConfirmed {
					countsByVuln[vt].autoConfirmed++
				} else {
					countsByVuln[vt].confirmed++
				}
			case "suspected":
				countsByVuln[vt].suspected++
			case "dismissed":
				// A machine (auto-confirmed) verdict the final review dismissed
				// is traceability the audit must not silently drop to 0 (A5):
				// count it apart so the report can say "N machine verdicts were
				// reviewed-out" instead of leaving the Auto-confirmed column at
				// 0 with no explanation.
				if f.Status == db.StatusAutoConfirmed {
					countsByVuln[vt].reviewedOut++
				}
			}
		}

		dismissedByType, err := store.CountCandidateVerdictsByType(ctx, scanID)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to count dismissed verdicts: %v", err))
			return 1
		}
		audits := make([]vulnAuditEntry, 0, len(stats))
		for _, st := range stats {
			vc := countsByVuln[st.VulnType]
			if vc == nil {
				vc = &vulnCounts{}
			}
			unclassified := st.FinalCount - vc.confirmed - dismissedByType[st.VulnType]
			if unclassified < 0 {
				unclassified = 0
			}
			audits = append(audits, vulnAuditEntry{
				VulnType:        st.VulnType,
				SeedCount:       st.SeedCount,
				FinalCount:      st.FinalCount,
				Filters:         st.FilterChain,
				Confirmed:       vc.confirmed,
				Suspected:       vc.suspected,
				AutoConfirmed:   vc.autoConfirmed,
				AutoReviewedOut: vc.reviewedOut,
				AIStageStatus:   st.AIStageStatus,
				Dismissed:       dismissedByType[st.VulnType],
				Unclassified:    unclassified,
			})
		}

		outputDir := parseStringFlag(remaining, "output-dir")

		// The scan-scale + aggregate block every reader-facing artifact opens
		// with. It is built once here and shared by report.md, audit-report.md
		// and the `summary` field of this command's JSON envelope, so the three
		// can never disagree about how big the scan was or how many issues it
		// found. Verdict figures are re-derived from the findings table, never
		// from a second source.
		overview := buildScanOverview(ctx, store, scanID, stats, scanFindings, audits)
		overview.Partial = allowPartial
		// Completeness signals are computed regardless of --output-dir so a
		// `report --audit` run without an output dir still surfaces them: a
		// converged candidate with no persisted verdict is a silent false
		// negative unless the JSON the orchestrator reads says so.

		orphans, err := countFindingsWithoutScanID(ctx, store)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to count findings without scan_id: %v", err))
			return 1
		}

		// Machine (auto-confirmed) verdicts were written WITHOUT AI review; the
		// re-review pass is what corrects a wrong one. A type with 0 candidates
		// gets no subagent, so its auto-confirmed findings can be audited
		// unreviewed — a real defect then reaches the final report machine-stamped
		// and an FP reaches it as a false positive. Count them so the audit
		// envelope says so instead of finalizing silently.
		unreviewed, err := unreviewedAutoConfirmedCount(ctx, store, scanID)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to count unreviewed auto-confirmed findings: %v", err))
			return 1
		}

		if outputDir != "" {
			auditPath := filepath.Join(outputDir, "audit-report.md")
			if err := writeAuditReport(auditPath, scanID, audits, overview, aiTiming); err != nil {
				WriteErrorJSON(fmt.Sprintf("failed to write audit report: %v", err))
				return 1
			}
			// Regenerate result.sarif from the AI's persisted findings so the
			// machine-readable report carries the post-A5 verdict + reasoning +
			// fix, not just the candidate-stage evidence. Confirmed only — the AI
			// verdict is binary, so there is no suspected stage to export.
			sarifPath := filepath.Join(outputDir, report.SarifFile)
			writeSarif := report.WriteSarifFromFindings
			if allowPartial {
				writeSarif = report.WriteSarifFromFindingsPartial
			}
			if err := writeSarif(sarifPath, "", scanFindings); err != nil {
				WriteErrorJSON(fmt.Sprintf("failed to write result.sarif: %v", err))
				return 1
			}
			// Regenerate report.md from the AI's persisted findings so the
			// human-readable report shows confirmed verdicts only, not the
			// candidate-stage leads that writeReport emitted at scan time.
			reportPath := filepath.Join(outputDir, report.ReportFile)
			if err := report.WriteReportFromFindings(reportPath, "", scanFindings, overview); err != nil {
				WriteErrorJSON(fmt.Sprintf("failed to write report.md: %v", err))
				return 1
			}
			// Regenerate result.xlsx from the same persisted findings: a one-way
			// export for the development team to locate, analyze, and confirm
			// every actionable finding inside a spreadsheet (dismissed excluded).
			xlsxPath := filepath.Join(outputDir, report.ResultXlsxFile)
			if err := report.WriteXlsxFromFindings(xlsxPath, "", scanFindings); err != nil {
				WriteErrorJSON(fmt.Sprintf("failed to write result.xlsx: %v", err))
				return 1
			}
			// pipeline-dismissed.json is the tool's AI-dismissal ledger (P1-8):
			// the dismissed verdicts persisted in candidate_verdicts are rendered
			// here so the customer can see what the AI rejected and why. It is
			// deliberately NOT named ai-dismissed.json — that filename belongs to
			// the orchestrator's own human-review recall ledger (needs_context +
			// per-type dismissed counts), and overwriting it here would wipe the
			// entries that live only in the orchestrator's aggregation.
			if verdicts, verr := store.ListCandidateVerdicts(ctx, scanID); verr == nil {
				type dismissedRow struct {
					VulnType string `json:"vuln_type"`
					File     string `json:"file"`
					Line     int    `json:"line"`
					Function string `json:"function,omitempty"`
					Variable string `json:"variable,omitempty"`
					Reason   string `json:"reason,omitempty"`
				}
				rows := make([]dismissedRow, 0, len(verdicts))
				for _, v := range verdicts {
					rows = append(rows, dismissedRow{VulnType: v.VulnType, File: v.FilePath, Line: v.LineNumber, Function: v.FunctionName, Variable: v.Variable, Reason: v.Reason})
				}
				if data, merr := json.MarshalIndent(map[string]interface{}{"scan_id": scanID, "total_dismissed": len(rows), "dismissed": rows}, "", "  "); merr == nil {
					_ = os.WriteFile(filepath.Join(outputDir, "pipeline-dismissed.json"), append(data, '\n'), 0644)
				}
			}
			// Rebuild findings/ from the DB so the review surface holds exactly
			// the actionable verdicts: dismissed entries and never-classified
			// leftovers are swept out instead of being handed to a reviewer.
			rec, err := report.ReconcileFindings(outputDir, scanFindings)
			if err != nil {
				WriteErrorJSON(fmt.Sprintf("failed to reconcile findings dir: %v", err))
				return 1
			}
			out := map[string]interface{}{
				"scan_id":         scanID,
				"audit_path":      auditPath,
				"sarif_path":      sarifPath,
				"report_path":     reportPath,
				"xlsx_path":       xlsxPath,
				"vuln_count":      len(audits),
				"findings_synced": rec,
				"status":          "ok",
				// The orchestrator needs the per-type verdict breakdown to build
				// its report and reconcile subagent counts. Without it here, it
				// falls back to a raw `secguard db` query over findings and
				// guesses a nonexistent column (type instead of rule_id), which
				// costs a schema-discovery round-trip.
				"audits": audits,
				// The aggregate the per-type breakdown lacks: scan scale (files /
				// functions / lines) plus the confirmed/dismissed totals and the
				// one-line headline. It is the same object
				// report.md renders, so echoing `summary` into the console can
				// never contradict the report — and the orchestrator never has to
				// add up `audits` itself (the console used to show per-type
				// counts with no total at all).
				"summary": overview.SummaryFields(),
			}
			if allowPartial {
				out["partial"] = true
			}
			// The engine-measured AI stage (total + per type) so the orchestrator
			// can report it without hand-estimating a wall clock. Omitted when the
			// scan has no settlement timing at all.
			if aiTiming.TotalMS > 0 {
				out["ai_stage"] = aiTiming
			}

			// A finding with no scan_id has no scan directory, so its verdict
			// file cannot be placed or reconciled. Surface it instead of
			// letting the review surface be quietly incomplete.
			auditNoticeFields(out, orphans, unreviewed, overview.Unclassified)
			// findings/ is a projection of the DB, so its file count must equal
			// the number of confirmed results the same invocation just wrote to
			// result.sarif. If a confirmed row could not be placed (an unmapped
			// rule_id with no known vuln_type, a write error), say so instead of
			// shipping a review surface that is silently short.
			confirmedResults := 0
			for _, f := range scanFindings {
				if f.FinalStatus() == "confirmed" {
					confirmedResults++
				}
			}
			if rec.Written != confirmedResults {
				msg := fmt.Sprintf("%s/ holds %d file(s) for %d confirmed finding(s) — the review surface does not match the DB/result.sarif", report.FindingsDir, rec.Written, confirmedResults)
				if prev, ok := out["warning"].(string); ok && prev != "" {
					msg = prev + "; " + msg
				}
				out["warning"] = msg
			}
			WriteJSON(out)
		} else {
			out := map[string]interface{}{
				"scan_id": scanID,
				"audits":  audits,
				"summary": overview.SummaryFields(),
			}
			if allowPartial {
				out["partial"] = true
			}
			if aiTiming.TotalMS > 0 {
				out["ai_stage"] = aiTiming
			}
			auditNoticeFields(out, orphans, unreviewed, overview.Unclassified)
			WriteJSON(out)
		}
		return 0
	}

	// The read action is now explicit. Reaching this point WITHOUT --list means
	// no recognized action flag was passed at all: a mangled/typo'd flag (or a
	// caller that concatenated flags into one argv element) would otherwise
	// degrade into silently dumping the whole findings table. Fail loud instead.
	if !hasFlag(remaining, "list") {
		printReportUsage()
		WriteErrorJSON("no action flag: pass --list (read all findings), --stats (read-only per-type verdicts), --write-json (persist), --list-auto-confirmed (re-review), --review-json, --complete-type, or --audit")
		return 1
	}

	statusFilter := parseStringFlag(remaining, "status")
	scanID := parseStringFlag(remaining, "scan-id")

	var findings []*db.Finding
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
	WriteJSON(out)
	return 0
}

// buildScanOverview assembles the scan-scale + aggregate block shared by
// report.md, audit-report.md and the `summary` envelope field.
//
// Verdict figures come from `audits` (itself derived from the findings table) so
// every reader-facing artifact counts the same rows; scan-scale figures come from
// the `scan_runs` row the scan wrote, with the indexed `files` table as the
// fallback for scans that predate that table or for review runs that never write
// one. A missing metrics row degrades to "n/a" — it is never reported as a scan
// of 0 files, which would read as an empty codebase.
func buildScanOverview(ctx context.Context, store db.Store, scanID string, stats []*db.ScanStat, findings []*db.Finding, audits []vulnAuditEntry) report.ScanOverview {
	ov := report.ScanOverview{
		ScanID:         scanID,
		Tool:           "secguard-clang v" + report.ToolVersion,
		SeverityCounts: report.CountSeverities(findings),
		TypesScanned:   len(stats),
	}
	for _, a := range audits {
		ov.RawSeeds += a.SeedCount
		ov.Candidates += a.FinalCount
		if a.FinalCount > 0 {
			ov.TypesWithCandidates++
		}
		ov.AutoConfirmed += a.AutoConfirmed
		ov.AIConfirmed += a.Confirmed
		ov.AISuspected += a.Suspected

		if a.AutoConfirmed+a.Confirmed+a.Suspected > 0 {
			ov.TypesWithFindings++
		}
	}
	// Dismissed comes from the persisted candidate_verdicts ledger, and
	// unclassified is the honest residue: a candidate nobody ever classified is
	// NOT a dismissal. The old Candidates-AIConfirmed residue hid unfinished
	// ranges behind a "dismissed, unclassified=0" summary.
	for _, a := range audits {
		ov.AIDismissed += a.Dismissed
		ov.Unclassified += a.Unclassified
	}

	if run, err := store.GetScanRun(ctx, scanID); err == nil && run != nil {
		ov.HasScanMetrics = true
		ov.FilesIndexed = run.FilesIndexed
		ov.FunctionsIndexed = run.FunctionsIndexed
		ov.DurationMs = run.DurationMs
		ov.AIDurationMs = run.AIDurationMs
		ov.ScanMode = run.ScanMode
		if run.CreatedAt > 0 {
			ov.StartedAt = time.Unix(run.CreatedAt, 0)
		}
	}

	if files, err := store.ListFiles(ctx); err == nil {
		// FilesInIndex is the whole-graph figure the renderer falls back to when
		// this scan wrote no metrics row; FilesIndexed stays whatever the scan
		// measured (0 = not measured) so the two are never conflated.
		ov.FilesInIndex = len(files)
		for _, f := range files {
			ov.LinesOfCode += f.LOC
		}
		ov.TargetPath = indexPathRoot(files)
	}
	if funcs, err := store.CountFunctions(ctx); err == nil {
		ov.FunctionsInIndex = funcs
	}
	return ov
}

// indexPathRoot returns the directory the indexed files live under: the longest
// common directory prefix of every indexed path. scan_runs stores no target
// path, and the project root the DB lives in may be a PARENT of what was
// scanned (`secguard scan src/`), so the indexed paths are the only honest
// source for "what was scanned".
func indexPathRoot(files []*db.File) string {
	if len(files) == 0 {
		return ""
	}
	root := filepath.Dir(files[0].Path)
	for _, f := range files[1:] {
		dir := filepath.Dir(f.Path)
		for !strings.HasPrefix(dir+string(filepath.Separator), root+string(filepath.Separator)) {
			parent := filepath.Dir(root)
			if parent == root {
				return root
			}
			root = parent
		}
	}
	return root
}

type vulnAuditEntry struct {
	VulnType        string `json:"vuln_type"`
	SeedCount       int    `json:"seed_count"`
	FinalCount      int    `json:"final_count"`
	Filters         string `json:"filter_chain"`
	Confirmed       int    `json:"confirmed"`
	Suspected       int    `json:"suspected"`
	AutoConfirmed   int    `json:"auto_confirmed"`
	AutoReviewedOut int    `json:"auto_confirmed_reviewed_out"`
	AIStageStatus   string `json:"ai_stage_status"`
	// Dismissed is the persisted AI-dismissed verdict count (candidate_verdicts
	// ledger), never a Candidates-Confirmed residue: an unclassified candidate
	// must show up in Unclassified, not masquerade as reviewed-and-dismissed.
	Dismissed    int `json:"dismissed"`
	Unclassified int `json:"unclassified"`
}

func writeAuditReport(auditPath, scanID string, audits []vulnAuditEntry, overview report.ScanOverview, timing aiStageTiming) error {
	if err := os.MkdirAll(filepath.Dir(auditPath), 0755); err != nil {
		return err
	}
	// The overview carries the id it was built for; an explicitly passed id wins
	// so the header can never render without one.
	if overview.ScanID == "" {
		overview.ScanID = scanID
	}

	// A type with no converged candidate has nothing to show in the per-skill
	// table; listing 15 of them as zero rows buries the types that do. They are
	// folded into one collapsible section and labelled "no evidence" (or "all
	// filtered out" when the pipeline did receive raw seeds for them).
	var withCandidates, noCandidates []vulnAuditEntry
	for _, a := range audits {
		if a.FinalCount > 0 {
			withCandidates = append(withCandidates, a)
		} else {
			noCandidates = append(noCandidates, a)
		}
	}

	var b strings.Builder
	b.WriteString("# SecGuard Audit Report\n\n")
	// The same scale + aggregate header report.md opens with: an audit without
	// "how big was this scan" and "what was the bottom line" made the two
	// artifacts answer different questions from the same scan.
	b.WriteString(overview.MetadataMarkdown())
	b.WriteString(overview.HeadlineMarkdown())
	b.WriteString("## Per-Skill Pipeline Statistics\n\n")
	b.WriteString("| Vulnerability Type | Seed | Final | Auto-confirmed | AI Confirmed | AI Stage | Filter Efficiency |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")

	totalSeed, totalFinal, totalAutoConfirmed, totalConfirmed := 0, 0, 0, 0
	for _, a := range audits {
		totalSeed += a.SeedCount
		totalFinal += a.FinalCount
		totalAutoConfirmed += a.AutoConfirmed
		totalConfirmed += a.Confirmed
	}
	for _, a := range withCandidates {
		filterEff := "n/a"
		if a.SeedCount > 0 {
			filterEff = fmt.Sprintf("%.0f%%", float64(a.SeedCount-a.FinalCount)/float64(a.SeedCount)*100)
		}
		b.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d | %s | %s |\n",
			a.VulnType, a.SeedCount, a.FinalCount, a.AutoConfirmed, a.Confirmed, a.AIStageStatus, filterEff))
	}

	b.WriteString(fmt.Sprintf("| **TOTAL** | **%d** | **%d** | **%d** | **%d** | — |", totalSeed, totalFinal, totalAutoConfirmed, totalConfirmed))
	if totalSeed > 0 {
		b.WriteString(fmt.Sprintf(" **%.0f%%** |\n\n", float64(totalSeed-totalFinal)/float64(totalSeed)*100))
	} else {
		b.WriteString(" n/a |\n\n")
	}
	if len(noCandidates) > 0 {
		fmt.Fprintf(&b, "_%d type(s) produced no converged candidate and are folded below; their seed counts are included in the TOTAL row._\n\n", len(noCandidates))
		b.WriteString(fmt.Sprintf("<details>\n<summary>Types with no converged candidates (%d) — no evidence</summary>\n\n", len(noCandidates)))
		b.WriteString("| Vulnerability Type | Raw seeds | Final | AI Stage | Status |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, a := range noCandidates {
			status := "no evidence (0 raw seeds)"
			if a.SeedCount > 0 {
				status = fmt.Sprintf("all filtered out (%d raw seeds)", a.SeedCount)
			}
			b.WriteString(fmt.Sprintf("| %s | %d | %d | %s | %s |\n",
				a.VulnType, a.SeedCount, a.FinalCount, a.AIStageStatus, status))
		}
		b.WriteString("\n</details>\n\n")
	}

	// AI Value Summary: make the human impact of the AI classification layer
	// explicit and auditable. Every converged candidate should receive a
	// classification; a nonzero "without AI classification" count is a process
	// gap (e.g. a candidate whose skill was not loaded), not a design feature.
	b.WriteString("## AI Value Summary\n\n")
	b.WriteString("| Metric | Value |\n")
	b.WriteString("|--------|-------|\n")
	fmt.Fprintf(&b, "| Raw evidence seeds | %d |\n", totalSeed)
	fmt.Fprintf(&b, "| Auto-confirmed by pipeline | %d |\n", totalAutoConfirmed)
	if totalReviewedOut := auditReviewedOutTotal(audits); totalReviewedOut > 0 {
		fmt.Fprintf(&b, "| Auto-confirmed reviewed-out by final review | %d |\n", totalReviewedOut)
	}
	fmt.Fprintf(&b, "| Candidates needing AI review (suspected/possible) | %d |\n", totalFinal)
	fmt.Fprintf(&b, "| AI confirmed (actionable, with fix suggestion) | %d |\n", totalConfirmed)
	fmt.Fprintf(&b, "| Actionable findings for human review (confirmed) | %d |\n", totalAutoConfirmed+totalConfirmed)
	if totalSeed > 0 {
		fmt.Fprintf(&b, "| Pipeline filter efficiency | %.0f%% |\n\n", float64(totalSeed-totalFinal)/float64(totalSeed)*100)
	} else {
		b.WriteString("| Pipeline filter efficiency | n/a |\n\n")
	}

	b.WriteString(renderAITimingMarkdown(timing))

	b.WriteString("## Filter Chain Details\n\n")
	if len(withCandidates) == 0 {
		b.WriteString("No converged candidate reached the filter detail stage.\n\n")
	}
	for _, a := range withCandidates {
		b.WriteString(fmt.Sprintf("### %s\n\n", a.VulnType))
		b.WriteString(fmt.Sprintf("- **Seed count:** %d\n", a.SeedCount))
		b.WriteString(fmt.Sprintf("- **Final count:** %d\n", a.FinalCount))
		b.WriteString(fmt.Sprintf("- **AI classification:** auto-confirmed=%d, confirmed=%d, ai_stage_status=%s", a.AutoConfirmed, a.Confirmed, a.AIStageStatus))
		if a.AutoReviewedOut > 0 {
			b.WriteString(fmt.Sprintf(", auto-confirmed reviewed-out=%d", a.AutoReviewedOut))
		}
		b.WriteString("\n\n")
		if chain := renderFilterChainMarkdown(a.Filters); chain != "" {
			b.WriteString(chain)
			b.WriteString("\n")
		}
	}

	return os.WriteFile(auditPath, []byte(b.String()), 0644)
}

// renderAITimingMarkdown renders the engine-measured AI stage. It is empty when
// the scan has no settlement timing at all (e.g. a pipeline-only run), so the
// report never claims a duration it did not measure.
func renderAITimingMarkdown(timing aiStageTiming) string {
	if timing.TotalMS <= 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## AI Classification Timing\n\n")
	switch timing.Source {
	case "override":
		b.WriteString("_Total supplied by the `--ai-duration-ms` override; per-type spans are self-measured from settlement report timestamps._\n\n")
	case "self-measured", "":
		b.WriteString("_Self-measured by the engine from settlement report timestamps — no manual estimate._\n\n")
	default:
		fmt.Fprintf(&b, "_Source: %s._\n\n", timing.Source)
	}
	b.WriteString("| Scope | Batches | Elapsed |\n")
	b.WriteString("|---|---|---|\n")
	fmt.Fprintf(&b, "| **TOTAL AI stage** | %d | %s |\n", timing.Batches, formatMS(timing.TotalMS))
	for _, vt := range timing.sortedAITypes() {
		fmt.Fprintf(&b, "| %s | %d | %s |\n", vt, timing.PerTypeBatches[vt], formatMS(timing.PerTypeMS[vt]))
	}
	b.WriteString("\n")
	return b.String()
}

// renderFilterChainMarkdown turns the planner's stored filter-chain JSON into a
// table a reader can scan: each filter's input → output, its shrink ratio, and
// how many candidates it removed, with the largest bottleneck highlighted. The
// raw JSON it replaces was one several-hundred-character line in which the 80%
// filter was indistinguishable from a no-op.
func renderFilterChainMarkdown(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	var filters []planner.FilterStats
	if err := json.Unmarshal([]byte(raw), &filters); err != nil || len(filters) == 0 {
		// A chain written by an older/corrupt build is still shown, just not
		// tabulated: never hide the fact that a filter chain exists.
		return fmt.Sprintf("- **Filter chain (raw):** `%s`\n", raw)
	}
	topIdx, topRemoved := -1, 0
	for i, f := range filters {
		if removed := f.InputCount - f.OutputCount; removed > topRemoved {
			topIdx, topRemoved = i, removed
		}
	}
	var b strings.Builder
	b.WriteString("| Filter | Input | Output | Shrink | Removed |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for i, f := range filters {
		shrink := "—"
		if f.InputCount > 0 {
			shrink = fmt.Sprintf("%.0f%%", float64(f.InputCount-f.OutputCount)/float64(f.InputCount)*100)
		}
		name := f.Name
		if i == topIdx {
			name = "**" + name + "**"
		}
		b.WriteString(fmt.Sprintf("| %s | %d | %d | %s | %d |\n",
			name, f.InputCount, f.OutputCount, shrink, f.InputCount-f.OutputCount))
	}
	if topIdx >= 0 {
		f := filters[topIdx]
		ratio := 0.0
		if f.InputCount > 0 {
			ratio = float64(f.InputCount-f.OutputCount) / float64(f.InputCount) * 100
		}
		fmt.Fprintf(&b, "\n**Top shrink:** `%s` — removed %d candidates (%.0f%% of its input).\n",
			f.Name, topRemoved, ratio)
	}
	return b.String()
}

// auditReviewedOutTotal sums the auto-confirmed findings the final review
// dismissed, for the AI Value Summary aggregate line.
func auditReviewedOutTotal(audits []vulnAuditEntry) int {
	total := 0
	for _, a := range audits {
		total += a.AutoReviewedOut
	}
	return total
}

func resolveScanDir(args []string, scanID string) string {
	outputDir := parseStringFlag(args, "output-dir")
	if outputDir != "" {
		return outputDir
	}
	if scanID == "" {
		return ""
	}
	cwd, err := os.Getwd()
	if err != nil || cwd == "" {
		return ""
	}
	return filepath.Join(cwd, report.CodeagentDir, report.ProductDir, report.ScansDir, scanID)
}

// perFindingOutcome carries what the per-finding markdown writer did, plus a
// human-readable warning when it did nothing. The warning is the point: before
// 0.3.6 a failed rewrite was silent, so a whole classification pass could land
// in the DB while findings/ still showed unclassified candidates.
type perFindingOutcome struct {
	Path    string
	Action  string
	Warning string
}

func syncPerFindingAfterWrite(args []string, finding *db.Finding) perFindingOutcome {
	if finding.FilePath == "" || finding.LineNumber <= 0 {
		return perFindingOutcome{Action: "skipped", Warning: "per-finding markdown not written: finding carries no file/line"}
	}
	scanDir := resolveScanDir(args, finding.ScanID)
	if scanDir == "" {
		return perFindingOutcome{Action: "skipped", Warning: fmt.Sprintf(
			"per-finding markdown not written: no scan directory resolved — pass --scan-id (or --output-dir) so the verdict file lands under %s/<vuln-type>/", report.FindingsDir)}
	}
	if _, err := os.Stat(scanDir); err != nil {
		return perFindingOutcome{Action: "skipped", Warning: fmt.Sprintf(
			"per-finding markdown not written: scan dir %s is not readable (%v) — pass --output-dir pointing at the scan directory", scanDir, err)}
	}
	vulnType := finding.VulnType
	if vulnType != "" {
		if _, err := planner.GetVulnTypeSpec(vulnType); err != nil {
			vulnType = ""
		}
	}
	if vulnType == "" {
		vulnType = planner.TypeForCWE(finding.RuleID)
	}
	if vulnType == "" {
		return perFindingOutcome{Action: "skipped", Warning: fmt.Sprintf(
			"per-finding markdown not written: rule_id %q maps to no pipeline vulnerability type", finding.RuleID)}
	}
	res, err := report.SyncPerFinding(scanDir, vulnType, finding.FilePath, finding.LineNumber, report.PerFindingUpdate{
		Summary:        finding.Summary,
		Reasoning:      finding.Reasoning,
		FixStrategy:    finding.FixStrategy,
		ExceptionCheck: finding.ExceptionCheck,
		Status:         finding.EffectiveStatus(),
		Severity:       finding.Severity,
		Confidence:     finding.Confidence,
		FunctionName:   finding.FunctionName,
		Variable:       finding.Variable,
		Evidence:       finding.Evidence,
		CWE:            finding.RuleID,
	})
	if err != nil {
		return perFindingOutcome{Action: "error", Warning: fmt.Sprintf("per-finding markdown failed: %v", err)}
	}
	oc := perFindingOutcome{Path: res.Path, Action: res.Action}
	if res.Verdict == "" {
		oc.Warning = fmt.Sprintf("status %q carries no verdict, so %s/ was left untouched (expected confirmed|dismissed)",
			finding.Status, report.FindingsDir)
	}
	return oc
}

// countFindingsWithoutScanID reports how many findings cannot be placed in any
// scan's findings/ directory because they carry no scan_id.
func countFindingsWithoutScanID(ctx context.Context, store db.Store) (int, error) {
	// A COUNT must not materialize the whole findings table (21 columns incl.
	// evidence/reasoning) just to be len()'d — on a large repo this single
	// polling query allocated hundreds of MB and contended with 8 writers.
	var n int
	err := store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM findings WHERE scan_id IS NULL OR scan_id = ''`).Scan(&n)
	return n, err
}

// unreviewedAutoConfirmedCount returns how many findings for scanID carry a
// machine (auto-confirmed) verdict but no AI review verdict. The audit is the
// finalize step, so a non-zero count means the review pass has not covered every
// machine verdict — a wrong auto-confirm would otherwise be reported as-is.
func unreviewedAutoConfirmedCount(ctx context.Context, store db.Store, scanID string) (int, error) {
	var n int
	err := store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM findings WHERE scan_id = ? AND status = 'auto-confirmed' AND (review_status IS NULL OR review_status = '')`,
		scanID).Scan(&n)
	return n, err
}

// auditNoticeFields adds the completeness notices shared by both `report --audit`
// envelope shapes (with and without --output-dir) so the two can never drift:
// findings that cannot be placed in findings/, and machine verdicts that were
// never re-reviewed.
func auditNoticeFields(out map[string]interface{}, orphans, unreviewed, unclassified int) {
	var msgs []string
	if orphans > 0 {
		out["findings_without_scan_id"] = orphans
		msgs = append(msgs, fmt.Sprintf("%d finding(s) carry no scan_id and are missing from %s/ — re-write them with --scan-id", orphans, report.FindingsDir))
	}
	if unreviewed > 0 {
		out["unreviewed_auto_confirmed"] = unreviewed
		msgs = append(msgs, fmt.Sprintf("%d auto-confirmed finding(s) have no review verdict — re-review them (`report --list-auto-confirmed`, then `report --review-json`) before treating this audit as final", unreviewed))
	}
	if unclassified > 0 {
		out["unclassified_candidates"] = unclassified
		msgs = append(msgs, fmt.Sprintf("%d candidate(s) have no persisted verdict (unclassified) — they were never classified (not dismissed); re-dispatch their ranges before treating this audit as complete", unclassified))
	}
	if len(msgs) > 0 {
		out["warning"] = strings.Join(msgs, "; ")
	}
}

// findingInput is one row of a `--write-json` payload: the single-finding object
// shape, and the element type of the array/envelope shapes.
//
// The location keys are `file`/`line`/`function`, which differ from the findings
// table's `file_path`/`line_number`/`function_name` columns (and from the JSON
// `secguard db` / `report --list-auto-confirmed` emit for those columns). A
// payload that copies the DB spelling therefore decoded to the zero value and
// persisted a finding with an empty file_path and line 0, exit 0. The *Alias
// fields accept the column spelling too, and normalizeAliases folds it into the
// canonical fields — so both spellings now mean the same thing instead of one
// of them silently producing a location-less finding.
type findingInput struct {
	RuleID         string        `json:"rule_id"`
	VulnType       string        `json:"vuln_type"`
	Severity       string        `json:"severity"`
	Confidence     flexibleFloat `json:"confidence"`
	Status         string        `json:"status"`
	File           string        `json:"file"`
	Line           int           `json:"line"`
	Function       string        `json:"function"`
	Variable       string        `json:"variable"`
	Summary        string        `json:"summary"`
	Reasoning      string        `json:"reasoning"`
	ExceptionCheck string        `json:"exception_check"`
	FixStrategy    string        `json:"fix_strategy"`

	FilePathAlias   string `json:"file_path"`
	LineNumberAlias int    `json:"line_number"`
	FunctionAlias   string `json:"function_name"`
}

// normalizeAliases folds the DB-column spellings into the canonical
// file/line/function fields. The canonical value wins when both are present.
func (in *findingInput) normalizeAliases() {
	if in.File == "" {
		in.File = in.FilePathAlias
	}
	if in.Line == 0 {
		in.Line = in.LineNumberAlias
	}
	if in.Function == "" {
		in.Function = in.FunctionAlias
	}
}

// writeJSONShapeHint is appended to every parse failure. The batch path fails
// as a whole, so an opaque Go unmarshal error used to cost an agent a
// source-reading detour (or the whole type's findings) just to discover the
// accepted shape. The hint is intentionally concrete and one line long.
const writeJSONShapeHint = `Expected a JSON array of finding objects, e.g. ` +
	`[{"rule_id":"CWE-476","severity":"high","confidence":90,"status":"confirmed",` +
	`"file":"src/a.c","line":42,"function":"f","variable":"p","summary":"...","reasoning":"...",` +
	`"exception_check":"...","fix_strategy":"..."}]. ` +
	`A single finding object, or an object {"scan_id":"...","findings":[...]}, is also accepted.`

// parseWriteJSONInput accepts the three shapes an agent realistically writes and
// returns the findings plus any scan_id carried by the payload:
//
//   - the documented bare array of finding objects;
//   - an object envelope {"scan_id": ..., "findings": [...]};
//   - a single finding object (a one-element batch).
//
// Only the bare array is documented (see extension/shared/agent-body.md). The
// other two exist because a context-compacted agent loses the format spec and
// guesses the envelope, and a batch-wide parse failure then discards every
// finding of that type — observed in production. Accepting them is safe: the
// rows go through exactly the same per-row validation below, and an embedded
// scan_id is validated like the flag.
func parseWriteJSONInput(data []byte) ([]findingInput, string, bool, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, "", false, fmt.Errorf("input is empty")
	}
	inputs, scanID, err := parseWriteJSONStrict(trimmed)
	if err == nil {
		return inputs, scanID, false, nil
	}
	// Truncation salvage: a force-rejected / context-overflow write cuts the
	// batch mid-array, so the strict parse fails even though the leading objects
	// are complete. Recover the complete leading objects — but the batch is
	// explicitly PARTIAL (salvaged=true): the caller reports truncated:true and
	// exits non-zero, so a silently dropped tail can never pass for a full
	// settlement. An embedded scan_id survives via a loose extraction so the
	// salvaged rows still attach to the intended scan.
	if salvaged := salvageFindingObjects(trimmed); len(salvaged) > 0 {
		return salvaged, looseScanID(trimmed), true, nil
	}
	return nil, "", false, err
}

// looseScanID recovers an envelope's "scan_id" from a truncated payload whose
// strict parse failed. Only a top-level-looking string field is accepted;
// anything ambiguous yields "" and the caller falls back to --scan-id/latest.
func looseScanID(data []byte) string {
	re := regexp.MustCompile(`"scan_id"\s*:\s*"([^"]+)"`)
	m := re.FindSubmatch(data)
	if len(m) == 2 {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}

func parseWriteJSONStrict(trimmed []byte) ([]findingInput, string, error) {
	switch trimmed[0] {
	case '[':
		var inputs []findingInput
		if err := json.Unmarshal(trimmed, &inputs); err != nil {
			return nil, "", err
		}
		return inputs, "", nil
	case '{':
		// Probe for the envelope's keys before choosing a shape: `findings` may be
		// present-but-empty (`[]` / null), which must stay an envelope rather than
		// silently becoming an all-empty single finding.
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &probe); err != nil {
			return nil, "", err
		}
		raw, isEnvelope := probe["findings"]
		if !isEnvelope {
			var one findingInput
			if err := json.Unmarshal(trimmed, &one); err != nil {
				return nil, "", err
			}
			return []findingInput{one}, "", nil
		}
		var inputs []findingInput
		if err := json.Unmarshal(raw, &inputs); err != nil {
			return nil, "", fmt.Errorf(`the "findings" value is not an array of finding objects: %w`, err)
		}
		var scanID string
		if rawID, ok := probe["scan_id"]; ok {
			_ = json.Unmarshal(rawID, &scanID)
		}
		return inputs, strings.TrimSpace(scanID), nil
	default:
		return nil, "", fmt.Errorf("input is neither a JSON array nor an object (starts with %q)", string(trimmed[:1]))
	}
}

// salvageFindingObjects is the truncation-salvage fallback for a batch whose
// JSON was cut mid-write. It recovers every balanced {...} object (tracking JSON
// string boundaries so braces inside a string are ignored) and keeps the ones
// that parse as findings, so the complete leading findings survive.
func salvageFindingObjects(data []byte) []findingInput {
	var out []findingInput
	for _, span := range balancedObjects(data) {
		var in findingInput
		if err := json.Unmarshal(span, &in); err != nil {
			continue
		}
		if strings.TrimSpace(in.RuleID) == "" || strings.TrimSpace(in.Status) == "" {
			continue
		}
		out = append(out, in)
	}
	return out
}

// balancedObjects extracts balanced {...} object spans at the SHALLOWEST depth
// present in data (top-level array elements, or envelope members at that same
// depth), ignoring braces inside JSON strings (and escaped quotes). Restricting
// to the shallowest depth keeps a nested properties/evidence sub-object from
// being salvaged as an independent finding.
func balancedObjects(data []byte) [][]byte {
	type span struct {
		start, end, depth int
	}
	var spans []span
	var stack []int
	inString := false
	escaped := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{':
			stack = append(stack, i)
		case '}':
			if len(stack) > 0 {
				start := stack[len(stack)-1]
				depth := len(stack)
				stack = stack[:len(stack)-1]
				spans = append(spans, span{start, i + 1, depth})
			}
		}
	}
	minDepth := 0
	for _, sp := range spans {
		if minDepth == 0 || sp.depth < minDepth {
			minDepth = sp.depth
		}
	}
	var out [][]byte
	for _, sp := range spans {
		if sp.depth == minDepth {
			out = append(out, data[sp.start:sp.end])
		}
	}
	return out
}
