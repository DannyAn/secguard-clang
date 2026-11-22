package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

// removeBoolFlag removes a boolean flag (`--dry-run`, `--all`, `--list`) and its
// `--flag=value` spelling WITHOUT consuming the next argument. removeFlag treats
// every exact `--flag` match as a value flag and swallows the following token, so
// `--dry-run --batch-size 3` would drop `--batch-size` and leave a stray `3`
// (issue #275 P2-2).
func removeBoolFlag(args []string, flag string) []string {
	flagName := "--" + flag
	prefix := flagName + "="
	result := make([]string, 0, len(args))
	for _, a := range args {
		if a == flagName || strings.HasPrefix(a, prefix) {
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
// to the canonical absolute path stored in the files table. An ABSOLUTE path
// that is not one of the indexed files returns "" so the caller can reject it —
// an unindexed absolute path would otherwise become an arbitrary-file read in
// `report --audit` (issue #275 P1-6). A relative path that resolves to nothing is
// best-effort: the input is returned unchanged, so a finding whose source cannot
// be located degrades to "no code context" instead of being silently rewritten.
//
// files is the pre-fetched indexed file list; pass it to amortize ListFiles
// across a whole --write-json batch. When nil, it is fetched lazily (fine for a
// single --write call).
func resolveFindingFilePath(ctx context.Context, store db.Store, file string, files []*db.File) string {
	if file == "" {
		return ""
	}
	if files == nil {
		files, _ = store.ListFiles(ctx)
	}
	if filepath.IsAbs(file) {
		clean := filepath.Clean(file)
		for _, f := range files {
			if filepath.Clean(f.Path) == clean {
				return clean
			}
		}
		return ""
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

	switch {
	case hasFlag(remaining, "list-auto-confirmed"):
		return runReportListAutoConfirmed(ctx, store, remaining)
	case hasFlag(remaining, "write"):
		return runReportWrite(ctx, store, remaining)
	case hasFlag(remaining, "write-json"):
		return runReportWriteJSON(ctx, store, remaining)
	case hasFlag(remaining, "complete-type"):
		return runReportCompleteType(ctx, store, remaining)
	case hasFlag(remaining, "review"):
		return runReportReview(ctx, store, remaining)
	case hasFlag(remaining, "review-json"):
		return runReportReviewJSON(ctx, store, remaining)
	case hasFlag(remaining, "stats"):
		return runReportStats(ctx, store, remaining)
	case hasFlag(remaining, "audit"):
		return runReportAudit(ctx, store, dbPath, remaining)
	case hasFlag(remaining, "list"):
		return runReportList(ctx, store, remaining)
	}

	// The read action is now explicit. Reaching this point means no recognized
	// action flag was passed at all: a mangled/typo'd flag (or a caller that
	// concatenated flags into one argv element) would otherwise degrade into
	// silently dumping the whole findings table. Fail loud instead.
	printReportUsage()
	WriteErrorJSON("no action flag: pass --list (read all findings), --stats (read-only per-type verdicts), --write-json (persist), --list-auto-confirmed (re-review), --review-json, --complete-type, or --audit")
	return 1
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
		ov.AutoReviewedOut += a.AutoReviewedOut
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

	// A type with no converged candidate AND no machine-confirmed finding has
	// nothing to show in the per-skill table; listing many of them as zero rows
	// buries the types that do. They are folded into one collapsible section and
	// labelled "no evidence" (or "all filtered out" when the pipeline did
	// receive raw seeds for them). A type whose seeds were all auto-confirmed
	// stays in the table (see the fold predicate below).
	var withCandidates, noCandidates []vulnAuditEntry
	for _, a := range audits {
		// A type whose seeds were all machine-confirmed (FinalCount == 0 but
		// AutoConfirmed > 0) has findings to report — it is NOT a "no evidence"
		// type. Folding it under "all filtered out" would both hide its
		// auto-confirmed findings from the per-skill table and mislabel a
		// successful machine proof as a filter drop.
		if a.FinalCount > 0 || a.AutoConfirmed > 0 || a.AutoReviewedOut > 0 {
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
		// Step 5.5 health signal (issue #263): the share of machine verdicts
		// the final review overturned. A rate that stays high means a
		// blind-spot pattern keeps being auto-confirmed — fix the first-pass
		// evidence model instead of relying on review to catch it every scan.
		if denom := totalAutoConfirmed + totalReviewedOut; denom > 0 {
			fmt.Fprintf(&b, "| Auto-confirm overturn rate (Step 5.5 health signal) | %.1f%% |\n",
				float64(totalReviewedOut)/float64(denom)*100)
		}
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
	b.WriteString("| Scope | Settled ranges | Elapsed |\n")
	b.WriteString("|---|---|---|\n")
	fmt.Fprintf(&b, "| **TOTAL AI stage** | %d | %s |\n", timing.SettledRanges, formatMS(timing.TotalMS))
	for _, vt := range timing.sortedAITypes() {
		fmt.Fprintf(&b, "| %s | %d | %s |\n", vt, timing.PerTypeRanges[vt], formatMS(timing.PerTypeMS[vt]))
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
