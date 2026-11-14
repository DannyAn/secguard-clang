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
	// Variable is the finding's variable (part of the DB identity). Two
	// confirmed findings can share one file:line — different variables at the
	// same statement — so the verdict-file lookup uses it to tell them apart.
	Variable string
	Evidence string
	// CWE is the exact rule_id the verdict file should render. When empty,
	// buildFindingDoc falls back to the vuln_type's canonical CWE.
	CWE string
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
// developer has to look at it. Only CONFIRMED is actionable: the AI verdict is
// binary, so everything else is dismissed and never reaches the review surface.
func actionable(verdict string) bool {
	return verdict == VerdictConfirmed
}

// statusSuffix maps a verdict to a self-describing filename suffix that lets a
// developer spot confirmed at a glance via `ls`.
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

// findingIdentity is the part of a finding's DB identity that can share one
// file:line: the full file path, function, variable, and exact CWE. Two
// confirmed findings may legitimately share a location (two variables
// dereferenced on one statement, or two sub-category CWEs of one vuln type), and
// each must get its own verdict file — otherwise findings/ holds fewer files than
// the DB/SARIF have results. The full file path disambiguates two files whose
// last-two-segments tails coincide (issue #275 P1-4).
type findingIdentity struct {
	file     string
	function string
	variable string
	cwe      string
}

// normalizeIdentityText collapses whitespace so a multi-line detector variable
// (types without a variable key use the raw expression as Variable) compares
// equal to the single-line form the evidence file renders.
func normalizeIdentityText(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// docVariable returns the variable recorded in an evidence/verdict file.
func docVariable(content string) (string, bool) {
	const prefix = "- **Variable:** `"
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, prefix) && strings.HasSuffix(line, "`") {
			return line[len(prefix) : len(line)-1], true
		}
	}
	return "", false
}

// docCWE returns the CWE recorded in an evidence/verdict file.
func docCWE(content string) (string, bool) {
	const prefix = "**CWE:** "
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(line[len(prefix):]), true
		}
	}
	return "", false
}

// docMatchesIdentity reports whether the file records exactly this finding.
func docMatchesIdentity(content string, id findingIdentity) bool {
	if id.file != "" {
		got := candidateFilePath(content, "")
		if got == "" || filepath.Clean(got) != filepath.Clean(id.file) {
			return false
		}
	}
	if id.function != "" && !strings.Contains(content, " in "+id.function+"\n") {
		return false
	}
	if id.variable != "" {
		got, ok := docVariable(content)
		if !ok || normalizeIdentityText(got) != normalizeIdentityText(id.variable) {
			return false
		}
	}
	if id.cwe != "" {
		got, ok := docCWE(content)
		if !ok || !strings.EqualFold(got, id.cwe) {
			return false
		}
	}
	return true
}

// docMatchesLegacyLocation matches a file written before identity fields were
// recorded (no Variable line) so an upgrade updates the old file in place
// instead of minting a duplicate. A file that already records a different
// variable or a different file path is never a fallback match.
func docMatchesLegacyLocation(content string, id findingIdentity) bool {
	if id.file != "" {
		got := candidateFilePath(content, "")
		if got == "" || filepath.Clean(got) != filepath.Clean(id.file) {
			return false
		}
	}
	if id.function != "" && !strings.Contains(content, " in "+id.function+"\n") {
		return false
	}
	if id.variable != "" {
		if _, ok := docVariable(content); ok {
			return false
		}
	}
	if id.cwe != "" {
		if got, ok := docCWE(content); ok && !strings.EqualFold(got, id.cwe) {
			return false
		}
	}
	return true
}

// locateByBase finds the file in dir named <NNN><base>[_<verdict>].md that
// belongs to the finding described by id. When several files share a location,
// the identity match wins; a pre-identity file is a fallback only for a finding
// whose variable is not recorded there.
func locateByBase(dir, base string, id findingIdentity) string {
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
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			continue
		}
		content := string(data)
		if docMatchesIdentity(content, id) {
			return path
		}
		if fallback == "" && docMatchesLegacyLocation(content, id) {
			fallback = path
		}
	}
	return fallback
}

// fileRecordsIdentity reports whether path already holds this finding (so a
// rewrite is an update, not an overwrite of a different finding at the same
// location).
func fileRecordsIdentity(path string, id findingIdentity) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return docMatchesIdentity(string(data), id)
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
	cwe := u.CWE
	if cwe == "" {
		cwe = VulnToCWE(vulnType)
	}
	b.WriteString(fmt.Sprintf("**CWE:** %s\n\n", cwe))

	b.WriteString("## Location\n\n")
	if loc := extractSection(candidate, "## Location"); loc != "" {
		b.WriteString(loc + "\n\n")
	} else {
		b.WriteString(fmt.Sprintf("- **File:** `%s:%d`\n", filePath, line))
		if u.FunctionName != "" {
			b.WriteString(fmt.Sprintf("- **Function:** `%s`\n", u.FunctionName))
		}
		if u.Variable != "" {
			b.WriteString(fmt.Sprintf("- **Variable:** `%s`\n", normalizeIdentityText(u.Variable)))
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
	updated := replaceLineByPrefix(content, "- **AI Verdict:**", line)
	if updated == content && !(verdict == VerdictDismissed && reason != "") {
		content = strings.TrimRight(content, "\n") + "\n\n## AI Verdict\n\n" + line + "\n"
	} else {
		content = updated
	}

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
// developer must act on, each named <NNN>_<file>_<line>_confirmed.md.
//   - confirmed → the verdict file is written (created if the candidate stage
//     never ran) and any stale file for the same location under a different
//     verdict is deleted.
//   - dismissed → no file is created and any previously written file for that
//     location is deleted; the verdict and its reason are recorded on the
//     candidate evidence file instead.
//   - suspected (legacy spelling, no longer written) → no file is created and
//     any stale file for that location is deleted; it reads as dismissed.
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

	// Candidate evidence files render the type's canonical CWE, not the exact
	// per-category rule id, so the candidate lookup matches on function+variable
	// only; the verdict lookup matches the exact CWE as well.
	candPath := locateByBase(candDir, base, findingIdentity{file: filePath, function: u.FunctionName, variable: u.Variable})
	candidate := ""
	if candPath != "" {
		data, err := os.ReadFile(candPath)
		if err != nil {
			return res, fmt.Errorf("read candidate evidence %s: %w", candPath, err)
		}
		candidate = string(data)
	}
	id := findingIdentity{file: filePath, function: u.FunctionName, variable: u.Variable, cwe: u.CWE}
	existing := locateByBase(findingsDir, base, id)

	if !actionable(res.Verdict) {
		switch res.Verdict {
		case VerdictDismissed:
			if candPath != "" {
				if err := annotateCandidate(candPath, VerdictDismissed, dismissReason(u), ""); err != nil {
					return res, err
				}
			}
		case VerdictSuspected:
			// Legacy spelling: remove any stale verdict file but do NOT annotate
			// the candidate as a false positive — it was never a binary dismissal.
		default:
			// no verdict at all (e.g. "open"): leave findings/ untouched.
			return res, nil
		}
		if existing != "" {
			if err := os.Remove(existing); err != nil {
				return res, fmt.Errorf("remove %s finding file %s: %w", res.Verdict, existing, err)
			}
			res.Action = PerFindingRemoved
		}
		return res, nil
	}

	// Keep an existing verdict file's sequence prefix so an update rewrites the
	// file in place; fall back to the candidate's prefix (the normal first
	// write), then to a fresh number for a finding with no evidence file.
	seq := seqPrefix(filepath.Base(existing))
	if seq == "" {
		seq = seqPrefix(filepath.Base(candPath))
	}
	if seq == "" {
		seq = nextSeq(findingsDir)
	}

	if err := os.MkdirAll(findingsDir, 0755); err != nil {
		return res, fmt.Errorf("create findings dir: %w", err)
	}
	name := seq + base + statusSuffix(res.Verdict) + ".md"
	newPath := filepath.Join(findingsDir, name)
	// A second confirmed finding at the same file:line (another variable, or
	// another sub-category CWE of the same type) shares the location-derived
	// base but is a separate finding: never overwrite the first one's file.
	if newPath != existing {
		if _, statErr := os.Stat(newPath); statErr == nil && !fileRecordsIdentity(newPath, id) {
			seq = nextSeq(findingsDir)
			name = seq + base + statusSuffix(res.Verdict) + ".md"
			newPath = filepath.Join(findingsDir, name)
		}
	}
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

// findingVulnType resolves the directory a finding belongs in. The finding's
// own vuln_type (validated against the registry) wins: multi-CWE subclasses
// (e.g. divide-by-zero's int_min_div carrying CWE-190) must stay attributed to
// their dispatched type, not be re-mapped to the CWE's canonical owner. The
// rule_id derivation is the fallback for legacy rows with an empty vuln_type.
func findingVulnType(f *db.Finding) string {
	if f.VulnType != "" {
		if _, err := planner.GetVulnTypeSpec(f.VulnType); err == nil {
			return f.VulnType
		}
	}
	if vt := planner.TypeForCWE(f.RuleID); vt != "" {
		return vt
	}
	return ""
}

// ReconcileFindings rebuilds findings/ from the database, which is the single
// source of truth for verdicts. It is the backstop for the failure mode that
// silently polluted findings/ before: a classification pass that wrote verdicts
// to the DB but never reached the per-finding writer (a missing scan id, an
// interrupted batch, a bulk dismissal explained only in chat) left dismissed
// and unclassified files sitting in the review surface.
//
// After it runs, findings/ holds exactly one file per confirmed finding of this
// scan, and nothing else (dismissed verdicts live in the DB only).
func ReconcileFindings(scanDir string, findings []*db.Finding) (ReconcileResult, error) {
	var res ReconcileResult
	if scanDir == "" {
		return res, nil
	}

	keep := map[string]bool{}
	for _, f := range latestPerLocation(findings, &res) {
		vulnType := findingVulnType(f)
		r, err := SyncPerFinding(scanDir, vulnType, f.FilePath, f.LineNumber, PerFindingUpdate{
			Summary:        f.Summary,
			Reasoning:      f.Reasoning,
			FixStrategy:    f.FixStrategy,
			ExceptionCheck: f.ExceptionCheck,
			Status:         f.FinalStatus(),
			Severity:       f.Severity,
			Confidence:     f.Confidence,
			FunctionName:   f.FunctionName,
			Variable:       f.Variable,
			Evidence:       f.Evidence,
			CWE:            f.RuleID,
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

// latestPerLocation collapses the finding list to one verdict per finding
// identity. The same finding can be written more than once (a re-run of a type
// batch, a corrected verdict), and findings/ is a projection of the CURRENT
// verdict — so the newest row (highest id, matching the ORDER BY id of the DB
// queries) wins instead of whichever row happens to be rendered last. The
// identity includes the rule_id: two sub-category CWEs of one type at the same
// location/variable are two findings in the DB and in result.sarif, so they must
// stay two entries here too.
func latestPerLocation(findings []*db.Finding, res *ReconcileResult) []*db.Finding {
	type key struct {
		vulnType string
		cwe      string
		file     string
		line     int
		function string
		variable string
	}
	order := make([]key, 0, len(findings))
	latest := make(map[key]*db.Finding, len(findings))
	for _, f := range findings {
		if f == nil {
			continue
		}
		vulnType := findingVulnType(f)
		if vulnType == "" {
			res.SkippedNoCWE++
			continue
		}
		k := key{vulnType, strings.ToUpper(strings.TrimSpace(f.RuleID)), filepath.Clean(f.FilePath), f.LineNumber, f.FunctionName, f.Variable}
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
