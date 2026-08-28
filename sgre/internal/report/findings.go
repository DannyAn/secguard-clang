package report

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

// The three verdicts a finding file can carry. findings/<vuln-type>/ is the
// human review surface, so only the actionable two ever produce a file there;
// a dismissed verdict is an audit record, not review work.
const (
	VerdictConfirmed = "confirmed"
	VerdictSuspected = "suspected"
	VerdictDismissed = "dismissed"
)

// Actions reported by SyncPerFinding.
const (
	PerFindingWritten = "written"
	PerFindingRemoved = "removed"
	PerFindingNone    = "none"
)

// PerFindingUpdate carries the AI agent's classification output for a single
// finding, which SyncPerFinding renders into findings/<vuln-type>/.
type PerFindingUpdate struct {
	Summary        string
	Reasoning      string
	FixStrategy    string
	ExceptionCheck string
	Status         string
	Severity       string
	Confidence     float64
	FunctionName   string
	Evidence       string
	// ContextLines overrides the global ContextLines for this finding; 0 means
	// "use the global setting", negative means "no source context".
	ContextLines int
}

// contextLines resolves the per-finding override against the global default.
func (u PerFindingUpdate) contextLines() int {
	if u.ContextLines != 0 {
		return u.ContextLines
	}
	return ContextLines
}

// PerFindingResult describes what SyncPerFinding did on disk. Path is empty for
// any verdict that must not appear under findings/ (dismissed, unclassified).
type PerFindingResult struct {
	Path    string
	Action  string
	Verdict string
}

// ReconcileResult summarizes a findings/ rebuild.
type ReconcileResult struct {
	Written      int      `json:"written"`
	Removed      int      `json:"removed"`
	SkippedNoCWE int      `json:"skipped_unmapped_cwe"`
	Errors       []string `json:"errors,omitempty"`
}

var seqRe = regexp.MustCompile(`^(\d{3,})_`)

// normalizeVerdict maps every status spelling the pipeline, the DB, and the
// agent use onto one of the three verdicts, or "" when the status carries no
// verdict at all (e.g. the DB default "open").
func normalizeVerdict(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case VerdictConfirmed, "auto-confirmed":
		return VerdictConfirmed
	case VerdictSuspected, "suspected-kept":
		return VerdictSuspected
	case VerdictDismissed, "false-positive", "false_positive", "falsepositive", "fp":
		return VerdictDismissed
	default:
		return ""
	}
}

// actionable reports whether a verdict belongs in findings/ — i.e. whether a
// developer has to look at it.
func actionable(verdict string) bool {
	return verdict == VerdictConfirmed || verdict == VerdictSuspected
}

// statusSuffix maps a verdict to a self-describing filename suffix that lets a
// developer spot confirmed/suspected at a glance via `ls`.
func statusSuffix(verdict string) string {
	if verdict == "" {
		return ""
	}
	return "_" + verdict
}

func trimVerdictSuffix(stem string) string {
	for _, s := range []string{"_" + VerdictConfirmed, "_" + VerdictSuspected, "_" + VerdictDismissed, "_pending"} {
		stem = strings.TrimSuffix(stem, s)
	}
	return stem
}

// findingBase is the location-derived filename tail shared by a candidate file
// and its verdict file: _<sanitized-file>_<line>.
func findingBase(filePath string, line int) string {
	return fmt.Sprintf("_%s_%d", sanitizeFilename(shortFile(filePath)), line)
}

// locateByBase finds the file in dir named <NNN><base>[_<verdict>].md. When
// several files share a location, the one whose title names functionName wins.
func locateByBase(dir, base, functionName string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	fallback := ""
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		stem := trimVerdictSuffix(strings.TrimSuffix(e.Name(), ".md"))
		if !strings.HasSuffix(stem, base) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if functionName == "" {
			return path
		}
		if data, err := os.ReadFile(path); err == nil &&
			strings.Contains(string(data), " in "+functionName+"\n") {
			return path
		}
		if fallback == "" {
			fallback = path
		}
	}
	return fallback
}

func seqPrefix(name string) string {
	if name == "" {
		return ""
	}
	if m := seqRe.FindStringSubmatch(name); m != nil {
		return m[1]
	}
	return ""
}

// nextSeq returns the next free NNN prefix in dir, so a finding with no
// candidate evidence file still gets a stable, ordered name.
func nextSeq(dir string) string {
	max := 0
	entries, err := os.ReadDir(dir)
	if err == nil {
		for _, e := range entries {
			if n, err := strconv.Atoi(seqPrefix(e.Name())); err == nil && n > max {
				max = n
			}
		}
	}
	return fmt.Sprintf("%03d", max+1)
}

// extractSection returns the body of a "## Heading" section, up to the next
// "## " heading or end of file, or "" when the heading is absent.
func extractSection(content, heading string) string {
	idx := strings.Index(content, heading+"\n")
	if idx < 0 {
		return ""
	}
	rest := content[idx+len(heading)+1:]
	if end := strings.Index(rest, "\n## "); end >= 0 {
		rest = rest[:end]
	}
	return strings.TrimSpace(rest)
}

// dropSectionToEnd removes a "## Heading" section and everything after it.
func dropSectionToEnd(content, heading string) string {
	idx := strings.Index(content, heading+"\n")
	if idx < 0 {
		return content
	}
	return content[:idx]
}

// replaceLineByPrefix swaps the single line starting with prefix for newLine,
// returning content unchanged when no such line exists.
func replaceLineByPrefix(content, prefix, newLine string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, prefix) {
			lines[i] = newLine
			return strings.Join(lines, "\n")
		}
	}
	return content
}

func firstLine(content string) string {
	if i := strings.Index(content, "\n"); i >= 0 {
		return content[:i]
	}
	return content
}

// candidateFilePath recovers the source path the pipeline recorded in a
// candidate file's Location block (`- **File:** ` + "`" + `/abs/path.c:42` + "`" + `),
// which is absolute and therefore the most reliable base for reading source.
// Falls back to the path the caller supplied.
func candidateFilePath(candidate, fallback string) string {
	loc := extractSection(candidate, "## Location")
	if loc == "" {
		return fallback
	}
	const prefix = "- **File:** `"
	idx := strings.Index(loc, prefix)
	if idx < 0 {
		return fallback
	}
	rest := loc[idx+len(prefix):]
	end := strings.Index(rest, "`")
	if end < 0 {
		return fallback
	}
	spec := rest[:end]
	if colon := strings.LastIndex(spec, ":"); colon > 0 {
		if _, err := strconv.Atoi(spec[colon+1:]); err == nil {
			spec = spec[:colon]
		}
	}
	if spec == "" {
		return fallback
	}
	return spec
}

// verdictStatusLine renders the Classification status line: the verdict plus
// the severity/confidence the AI attached to it.
func verdictStatusLine(verdict string, u PerFindingUpdate) string {
	line := "- **Status:** " + verdict
	if u.Severity != "" {
		line += fmt.Sprintf(" (severity: %s", strings.ToLower(u.Severity))
		if u.Confidence > 0 {
			line += fmt.Sprintf(", confidence: %.0f%%", u.Confidence*100)
		}
		line += ")"
	}
	return line
}

// buildFindingDoc renders the verdict file. It is built from the AI's output
// and enriched with the pipeline evidence from the candidate file when one
// exists, so the file is complete even if the candidate stage never ran (a
// direct `report --write` against an ad-hoc location).
func buildFindingDoc(vulnType, filePath string, line int, verdict string, u PerFindingUpdate, candidate, projectRoot string) string {
	var b strings.Builder

	head := firstLine(candidate)
	if !strings.HasPrefix(head, "# ") {
		fn := u.FunctionName
		if fn == "" {
			fn = "unknown function"
		}
		head = fmt.Sprintf("# %s in %s", title(vulnType), fn)
	}
	b.WriteString(head + "\n\n")
	b.WriteString(fmt.Sprintf("**CWE:** %s\n\n", VulnToCWE(vulnType)))

	b.WriteString("## Location\n\n")
	if loc := extractSection(candidate, "## Location"); loc != "" {
		b.WriteString(loc + "\n\n")
	} else {
		b.WriteString(fmt.Sprintf("- **File:** `%s:%d`\n", filePath, line))
		if u.FunctionName != "" {
			b.WriteString(fmt.Sprintf("- **Function:** `%s`\n", u.FunctionName))
		}
		b.WriteString("\n")
	}

	// The reviewer must be able to judge the finding without opening an editor,
	// so the source region travels with the verdict. The candidate file's
	// Location carries the absolute path, which is the most reliable source.
	if ctx := readCodeContext(candidateFilePath(candidate, filePath), line, u.contextLines(), projectRoot); ctx != nil {
		b.WriteString("## Code Context\n\n")
		fmt.Fprintf(&b, "`%s:%d-%d` — line %d is the reported location.\n\n", ctx.Path, ctx.StartLine, ctx.EndLine, ctx.Line)
		b.WriteString(ctx.render())
		b.WriteString("\n")
	}

	b.WriteString("## Evidence\n\n")
	ev := extractSection(candidate, "## Evidence")
	if ev == "" {
		ev = strings.TrimSpace(u.Evidence)
	}
	if ev == "" {
		ev = "- (no pipeline evidence package recorded for this location)"
	}
	b.WriteString(ev + "\n\n")

	b.WriteString("## Classification\n\n")
	b.WriteString(verdictStatusLine(verdict, u) + "\n\n")

	if u.Summary != "" {
		b.WriteString("## Summary\n\n" + u.Summary + "\n\n")
	}
	if u.Reasoning != "" {
		b.WriteString("## Reasoning\n\n" + u.Reasoning + "\n\n")
	}
	if u.ExceptionCheck != "" {
		b.WriteString("## Exception Check\n\n" + u.ExceptionCheck + "\n\n")
	}
	if u.FixStrategy != "" {
		b.WriteString("## Fix Strategy\n\n" + u.FixStrategy + "\n")
	} else if fix := extractSection(candidate, "## Fix Suggestion"); fix != "" {
		// No AI fix: keep the pipeline's generic suggestion rather than
		// handing the developer a finding with no remediation at all.
		b.WriteString("## Fix Suggestion\n\n" + fix + "\n")
	}

	return strings.TrimRight(b.String(), "\n") + "\n"
}

// annotateCandidate records the AI verdict on the candidate evidence file: the
// dismissal trail stays on disk and reviewers can jump from a candidate to its
// verdict file, without a false positive ever landing in findings/.
func annotateCandidate(candPath, verdict, reason, findingRel string) error {
	data, err := os.ReadFile(candPath)
	if err != nil {
		return fmt.Errorf("read candidate evidence %s: %w", candPath, err)
	}
	content := dropSectionToEnd(string(data), "## AI Verdict")

	line := "- **AI Verdict:** " + verdict
	switch {
	case findingRel != "":
		line += fmt.Sprintf(" — see `%s`", findingRel)
	case verdict == VerdictDismissed:
		line += " (false positive — excluded from `" + FindingsDir + "/`)"
	}
	content = replaceLineByPrefix(content, "- **AI Verdict:**", line)

	if verdict == VerdictDismissed && reason != "" {
		content = strings.TrimRight(content, "\n") +
			"\n\n## AI Verdict\n\n- **Status:** dismissed (false positive)\n- **Reason:** " + reason + "\n"
	}
	if err := os.WriteFile(candPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("annotate candidate evidence %s: %w", candPath, err)
	}
	return nil
}

func dismissReason(u PerFindingUpdate) string {
	for _, s := range []string{u.Reasoning, u.ExceptionCheck, u.Summary} {
		if t := strings.TrimSpace(s); t != "" {
			return t
		}
	}
	return ""
}

// SyncPerFinding makes findings/<vuln-type>/ match one AI verdict.
//
// The invariant it enforces: findings/ contains exactly the findings a
// developer must act on, each named <NNN>_<file>_<line>_<confirmed|suspected>.md.
//   - confirmed/suspected → the verdict file is written (created if the
//     candidate stage never ran) and any stale file for the same location under
//     a different verdict is deleted.
//   - dismissed → no file is created and any previously written file for that
//     location is deleted; the verdict and its reason are recorded on the
//     candidate evidence file instead.
//   - no verdict at all (e.g. status "open") → findings/ is left untouched.
func SyncPerFinding(scanDir, vulnType, filePath string, line int, u PerFindingUpdate) (PerFindingResult, error) {
	res := PerFindingResult{Action: PerFindingNone}
	if scanDir == "" || vulnType == "" || filePath == "" || line <= 0 {
		return res, nil
	}
	res.Verdict = normalizeVerdict(u.Status)

	base := findingBase(filePath, line)
	findingsDir := filepath.Join(scanDir, FindingsDir, vulnType)
	candDir := filepath.Join(scanDir, CandidatesDir, vulnType)

	candPath := locateByBase(candDir, base, u.FunctionName)
	candidate := ""
	if candPath != "" {
		data, err := os.ReadFile(candPath)
		if err != nil {
			return res, fmt.Errorf("read candidate evidence %s: %w", candPath, err)
		}
		candidate = string(data)
	}
	existing := locateByBase(findingsDir, base, u.FunctionName)

	if !actionable(res.Verdict) {
		if res.Verdict != VerdictDismissed {
			return res, nil
		}
		if candPath != "" {
			if err := annotateCandidate(candPath, VerdictDismissed, dismissReason(u), ""); err != nil {
				return res, err
			}
		}
		if existing != "" {
			if err := os.Remove(existing); err != nil {
				return res, fmt.Errorf("remove dismissed finding file %s: %w", existing, err)
			}
			res.Action = PerFindingRemoved
		}
		return res, nil
	}

	seq := seqPrefix(filepath.Base(candPath))
	if seq == "" {
		seq = seqPrefix(filepath.Base(existing))
	}
	if seq == "" {
		seq = nextSeq(findingsDir)
	}

	if err := os.MkdirAll(findingsDir, 0755); err != nil {
		return res, fmt.Errorf("create findings dir: %w", err)
	}
	name := seq + base + statusSuffix(res.Verdict) + ".md"
	newPath := filepath.Join(findingsDir, name)
	doc := buildFindingDoc(vulnType, filePath, line, res.Verdict, u, candidate, projectRootFromScanDir(scanDir))
	if err := os.WriteFile(newPath, []byte(doc), 0644); err != nil {
		return res, fmt.Errorf("write finding file %s: %w", newPath, err)
	}

	// Drop stale spellings of the same location (a previous verdict, or a
	// pre-0.3.6 candidate file that lived in findings/), so `ls` never shows
	// one finding twice under two verdicts.
	stale := []string{filepath.Join(findingsDir, seq+base+".md")}
	for _, v := range []string{VerdictConfirmed, VerdictSuspected, VerdictDismissed} {
		stale = append(stale, filepath.Join(findingsDir, seq+base+"_"+v+".md"))
	}
	if existing != "" {
		stale = append(stale, existing)
	}
	for _, p := range stale {
		if p == newPath {
			continue
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return res, fmt.Errorf("remove stale finding file %s: %w", p, err)
		}
	}

	if candPath != "" {
		if err := annotateCandidate(candPath, res.Verdict, "", filepath.Join(FindingsDir, vulnType, name)); err != nil {
			return res, err
		}
	}

	res.Action = PerFindingWritten
	res.Path = newPath
	return res, nil
}

// ReconcileFindings rebuilds findings/ from the database, which is the single
// source of truth for verdicts. It is the backstop for the failure mode that
// silently polluted findings/ before: a classification pass that wrote verdicts
// to the DB but never reached the per-finding writer (a missing scan id, an
// interrupted batch, a bulk dismissal explained only in chat) left dismissed
// and unclassified files sitting in the review surface.
//
// After it runs, findings/ holds exactly one file per confirmed/suspected
// finding of this scan, and nothing else.
func ReconcileFindings(scanDir string, findings []*db.Finding) (ReconcileResult, error) {
	var res ReconcileResult
	if scanDir == "" {
		return res, nil
	}

	keep := map[string]bool{}
	for _, f := range latestPerLocation(findings, &res) {
		vulnType := planner.TypeForCWE(f.RuleID)
		r, err := SyncPerFinding(scanDir, vulnType, f.FilePath, f.LineNumber, PerFindingUpdate{
			Summary:        f.Summary,
			Reasoning:      f.Reasoning,
			FixStrategy:    f.FixStrategy,
			ExceptionCheck: f.ExceptionCheck,
			Status:         f.FinalStatus(),
			Severity:       f.Severity,
			Confidence:     f.Confidence,
			FunctionName:   f.FunctionName,
			Evidence:       f.Evidence,
		})
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s:%d: %v", f.FilePath, f.LineNumber, err))
			continue
		}
		switch r.Action {
		case PerFindingWritten:
			res.Written++
			keep[r.Path] = true
		case PerFindingRemoved:
			res.Removed++
		}
	}

	root := filepath.Join(scanDir, FindingsDir)
	typeDirs, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return res, nil
		}
		return res, fmt.Errorf("read findings dir: %w", err)
	}
	for _, td := range typeDirs {
		if !td.IsDir() {
			continue
		}
		dir := filepath.Join(root, td.Name())
		files, err := os.ReadDir(dir)
		if err != nil {
			return res, fmt.Errorf("read findings dir %s: %w", dir, err)
		}
		for _, fe := range files {
			if fe.IsDir() || !strings.HasSuffix(fe.Name(), ".md") {
				continue
			}
			path := filepath.Join(dir, fe.Name())
			if keep[path] {
				continue
			}
			if err := os.Remove(path); err != nil {
				return res, fmt.Errorf("remove orphan finding file %s: %w", path, err)
			}
			res.Removed++
		}
		if rest, err := os.ReadDir(dir); err == nil && len(rest) == 0 {
			_ = os.Remove(dir)
		}
	}
	return res, nil
}

// latestPerLocation collapses the finding list to one verdict per location.
// The same location can be written more than once (a re-run of a type batch, a
// corrected verdict), and findings/ is a projection of the CURRENT verdict — so
// the newest row (highest id, matching the ORDER BY id of the DB queries) wins
// instead of whichever row happens to be rendered last.
func latestPerLocation(findings []*db.Finding, res *ReconcileResult) []*db.Finding {
	type key struct {
		vulnType string
		file     string
		line     int
		function string
	}
	order := make([]key, 0, len(findings))
	latest := make(map[key]*db.Finding, len(findings))
	for _, f := range findings {
		if f == nil {
			continue
		}
		vulnType := planner.TypeForCWE(f.RuleID)
		if vulnType == "" {
			res.SkippedNoCWE++
			continue
		}
		k := key{vulnType, sanitizeFilename(shortFile(f.FilePath)), f.LineNumber, f.FunctionName}
		prev, seen := latest[k]
		if !seen {
			order = append(order, k)
		}
		if !seen || f.ID >= prev.ID {
			latest[k] = f
		}
	}
	out := make([]*db.Finding, 0, len(order))
	for _, k := range order {
		out = append(out, latest[k])
	}
	return out
}

// LatestScanID resolves the `latest` pointer under projectRoot to a scan id,
// so a `report --write` that forgot --scan-id still reaches the current scan's
// output directory instead of silently writing no file at all.
func LatestScanID(projectRoot string) string {
	scansDir := filepath.Join(projectRoot, CodeagentDir, ProductDir, ScansDir)
	if target, err := os.Readlink(filepath.Join(scansDir, LatestName)); err == nil {
		return filepath.Base(strings.TrimSpace(target))
	}
	if data, err := os.ReadFile(filepath.Join(scansDir, LatestTxtName)); err == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}
