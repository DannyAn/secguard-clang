package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

// WriteReportFromFindings regenerates report.md from the AI's persisted findings,
// so the human-readable report carries the post-classification verdicts — not the
// candidate-stage leads that writeReport emits at scan time. Only CONFIRMED
// findings are listed; dismissed findings are excluded from the findings list,
// matching result.sarif and the findings/ directory.
//
// `overview` carries the scan-scale and pipeline-funnel figures (files /
// functions / lines scanned, raw seeds, converged candidates, auto-confirmed,
// durations). Its aggregate rows are recomputed here from `findings` when they
// disagree — a report that says "5 confirmed" must never be able to contradict
// the very list of findings printed below it. Pass the zero value when the scan
// metrics are unknown (older scans, unit tests): unknown values are omitted
// rather than rendered as a misleading 0.
//
// This is called from `report --audit` after the AI classification is persisted,
// overwriting the candidate-stage report.md so a reader never sees stale
// unclassified leads mixed with the final verdicts.
func WriteReportFromFindings(reportPath, rootDir string, findings []*db.Finding, overview ScanOverview) error {
	// Derive the project root from the report's scan directory when not given,
	// so file paths render repo-relative the same way result.sarif/result.xlsx
	// resolve them (and a reader can re-locate the source).
	sourceRoot := rootDir
	if sourceRoot == "" {
		sourceRoot = projectRootFromScanDir(filepath.Dir(reportPath))
	}

	type findingGroup struct {
		vulnType string
		cwe      string
		items    []*db.Finding
	}

	groups := []findingGroup{}
	groupIdx := map[string]int{}

	confirmed := 0
	autoConfirmed := 0
	for _, f := range findings {
		status := f.FinalStatus()
		switch status {
		case "confirmed":
			confirmed++
			if f.Status == db.StatusAutoConfirmed {
				autoConfirmed++
			}
		default:
			continue
		}
		cwe := strings.ToUpper(strings.TrimSpace(f.RuleID))
		if cwe == "" {
			cwe = "CWE-Other"
		}
		vulnType := planner.TypeForCWE(cwe)
		if vulnType == "" {
			vulnType = f.RuleID
		}
		if idx, ok := groupIdx[vulnType]; ok {
			groups[idx].items = append(groups[idx].items, f)
		} else {
			groupIdx[vulnType] = len(groups)
			groups = append(groups, findingGroup{vulnType: vulnType, cwe: cwe, items: []*db.Finding{f}})
		}
	}

	sort.Slice(groups, func(i, j int) bool {
		return groups[i].vulnType < groups[j].vulnType
	})

	// Every verdict figure is re-derived from `findings` — the list this report
	// prints below — so the aggregate rows can never disagree with it. Only the
	// scan-scale and pipeline-funnel figures come from the caller.
	overview.TypesWithFindings = len(groups)
	overview.SeverityCounts = CountSeverities(findings)
	overview.AutoConfirmed = autoConfirmed
	overview.AIConfirmed = confirmed - autoConfirmed
	overview.AISuspected = 0

	var b strings.Builder

	b.WriteString("# SecGuard Security Scan Report\n\n")
	b.WriteString("> This report reflects **AI-classified confirmed findings**.\n")
	b.WriteString("> Only confirmed findings are persisted; dismissed candidates are not recorded. Pipeline candidates are in `candidates/`.\n\n")

	b.WriteString(overview.MetadataMarkdown())
	b.WriteString(overview.VerdictMarkdown())

	b.WriteString("## Findings by Skill\n\n")
	// Auto-confirmed is broken out per type as well as in the aggregate: without
	// it the per-type "Confirmed" number mixed pipeline-proved and AI-classified
	// findings, so a reader reconciling report.md against findings/ had no way to
	// tell which rows were machine verdicts.
	b.WriteString("| Skill | CWE | Confirmed | Auto-confirmed |\n")
	b.WriteString("|-------|-----|-----------|----------------|\n")
	for _, g := range groups {
		auto := 0
		for _, f := range g.items {
			if f.Status == db.StatusAutoConfirmed {
				auto++
			}
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %d | %d |\n", g.vulnType, g.cwe, len(g.items), auto))
	}
	b.WriteString(fmt.Sprintf("| **TOTAL** | | **%d** | **%d** |\n\n", confirmed, autoConfirmed))

	for _, g := range groups {
		b.WriteString(fmt.Sprintf("## %s (%s)\n\n", g.vulnType, g.cwe))
		b.WriteString("| # | Status | Severity | Function | File:Line | Summary |\n")
		b.WriteString("|---|--------|----------|----------|-----------|---------|\n")
		for i, f := range g.items {
			// Show a repo-relative path when the root is known, else the raw
			// path — never the lossy shortFile tail, which drops intermediate
			// directories and breaks re-locating the file.
			fileShort := displayPath(f.FilePath, sourceRoot)
			summary := f.Summary
			if summary == "" {
				summary = f.Reasoning
			}
			if summary == "" {
				summary = f.Evidence
			}
			summary = strings.ReplaceAll(summary, "\n", " ")
			b.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s:%d | %s |\n",
				i+1, f.FinalStatus(), f.Severity, markdownCell(f.FunctionName), fileShort, f.LineNumber, markdownCell(summary)))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Output Files\n\n")
	b.WriteString(fmt.Sprintf("- SARIF (verdict stage, confirmed only): `%s`\n", SarifFile))
	b.WriteString(fmt.Sprintf("- Findings to review (confirmed: pipeline auto-confirmed + AI-classified): `%s/<vuln-type>/<NNN>_<file>_<line>_confirmed.md`\n", FindingsDir))
	b.WriteString(fmt.Sprintf("- Candidate evidence (pipeline output, pre-classification): `%s/<vuln-type>/`\n", CandidatesDir))
	b.WriteString("- Audit report (pipeline statistics): `audit-report.md`\n")
	b.WriteString("- Database: `.sgre/sgre.db`\n")

	return os.WriteFile(reportPath, []byte(b.String()), 0644)
}

func (o *ScanOutput) writeReport(packages []*planner.PlanResult, indexSummary IndexSummary) error {
	var b strings.Builder

	b.WriteString("# SecGuard Security Scan Report\n\n")
	b.WriteString("> This is the **candidate-stage** report (pipeline output, unclassified leads).\n")
	b.WriteString("> `report --audit` rewrites it once the AI has classified every candidate.\n\n")

	totalCandidates := 0
	typesWithCandidates := 0
	for _, pkg := range packages {
		totalCandidates += len(pkg.Candidates)
		if len(pkg.Candidates) > 0 {
			typesWithCandidates++
		}
	}

	overview := ScanOverview{
		ScanID:            o.ScanID,
		Tool:              "secguard-clang v" + ToolVersion,
		TargetPath:        indexSummary.TargetPath,
		StartedAt:         indexSummary.StartedAt,
		DurationMs:        indexSummary.DurationMs,
		FilesIndexed:      indexSummary.FilesIndexed,
		FunctionsIndexed:  indexSummary.FunctionsIndexed,
		FunctionsInIndex:  indexSummary.FunctionsInIndex,
		FilesInIndex:      indexSummary.FilesIndexed,
		LinesOfCode:       indexSummary.LinesOfCode,
		RawSeeds:          indexSummary.SeedCount,
		Candidates:        totalCandidates,
		AutoConfirmed:     indexSummary.AutoConfirmed,
		TypesScanned:      indexSummary.TypesScanned,
		TypesWithFindings: typesWithCandidates,
		// The scan's own walk figures are authoritative here (it just measured
		// them), so the "scanned" pair is the one to render.
		HasScanMetrics: true,
	}
	b.WriteString(overview.MetadataMarkdown())
	b.WriteString(overview.CandidateMarkdown())

	b.WriteString("## Candidates by Skill\n\n")
	b.WriteString("| Skill | CWE | Candidates | Auto-confirmed |\n")
	b.WriteString("|-------|-----|-----------|----------------|\n")
	for _, pkg := range packages {
		cwe := VulnToCWE(pkg.VulnerabilityType)
		auto := 0
		if indexSummary.AutoConfirmedByType != nil {
			auto = indexSummary.AutoConfirmedByType[pkg.VulnerabilityType]
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %d | %d |\n", pkg.VulnerabilityType, cwe, len(pkg.Candidates), auto))
	}
	b.WriteString(fmt.Sprintf("| **TOTAL** | | **%d** | **%d** |\n\n", totalCandidates, indexSummary.AutoConfirmed))

	// The per-candidate tables live in per-type index files under candidates/, so
	// a subagent assigned one type (or a candidate range of one type) reads only
	// its own slice instead of every type's table in one monolithic report.
	b.WriteString("## Per-Type Candidate Indexes\n\n")
	b.WriteString(fmt.Sprintf("Each type's candidate table (with the `Source` column the AI classifies from) is in `%s/<vuln-type>/%s`.\n\n", CandidatesDir, TypeIndexFile))

	b.WriteString("## Output Files\n\n")
	b.WriteString(fmt.Sprintf("- SARIF (candidate stage, level `note` — unclassified leads): `%s`\n", CandidatesSarifFile))
	b.WriteString(fmt.Sprintf("- SARIF (verdict stage, written by `report --audit`): `%s`\n", SarifFile))
	b.WriteString(fmt.Sprintf("- Candidate evidence (pipeline output, NOT verdicts): `%s/<vuln-type>/<NNN>_<file>_<line>.md`\n", CandidatesDir))
	b.WriteString(fmt.Sprintf("- Findings to review (AI verdicts): `%s/<vuln-type>/<NNN>_<file>_<line>_confirmed.md`\n", FindingsDir))
	b.WriteString(fmt.Sprintf("  — written after AI classification. Dismissed (false-positive) entries never appear here; their verdict is recorded in the database and on the candidate file.\n"))
	b.WriteString(fmt.Sprintf("- Database: `.sgre/sgre.db`\n"))

	return os.WriteFile(o.ReportPath, []byte(b.String()), 0644)
}

// writeCandidates writes one markdown file per converged candidate under
// candidates/<vuln-type>/. These are evidence packages, not defects: the AI
// agent classifies them, and only the actionable verdicts get a file under
// findings/<vuln-type>/ (see SyncPerFinding).
func (o *ScanOutput) writeCandidates(packages []*planner.PlanResult) error {
	for _, pkg := range packages {
		if len(pkg.Candidates) == 0 {
			continue
		}

		dir := filepath.Join(o.ScanDir, CandidatesDir, pkg.VulnerabilityType)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}

		if err := o.writeTypeIndex(dir, pkg); err != nil {
			return err
		}

		for i, c := range pkg.Candidates {
			cwe := VulnToCWE(pkg.VulnerabilityType)

			filename := candidateFilename(i+1, c.Target.File, c.Target.Line)
			path := filepath.Join(dir, filename)

			var b strings.Builder
			b.WriteString(fmt.Sprintf("# %s in %s\n\n", title(pkg.VulnerabilityType), c.Target.Function))
			b.WriteString(fmt.Sprintf("**CWE:** %s\n\n", cwe))
			b.WriteString(fmt.Sprintf("> Pipeline **candidate evidence** — not a defect and not a verdict.\n"+
				"> Classified findings live in `%s/%s/`.\n\n", FindingsDir, pkg.VulnerabilityType))

			b.WriteString("## Location\n\n")
			b.WriteString(fmt.Sprintf("- **File:** `%s:%d`\n", c.Target.File, c.Target.Line))
			b.WriteString(fmt.Sprintf("- **Function:** `%s`\n", c.Target.Function))
			if c.Signature != "" {
				b.WriteString(fmt.Sprintf("- **Signature:** `%s`\n", c.Signature))
			}
			if c.Target.Variable != "" {
				// When the Variable column IS the expression fallback
				// (types without a variable key, e.g. unchecked-return), it
				// carries the detector's raw multi-line text — collapse it to
				// one line so the Location section does not render wrapped C.
				variableDisplay := c.Target.Variable
				if c.Expression != "" && variableDisplay == c.Expression {
					variableDisplay = strings.ReplaceAll(c.Expression, "\n", " ")
				}
				b.WriteString(fmt.Sprintf("- **Variable:** `%s`\n", variableDisplay))
			}
			// The full multi-line statement when the detector captured one and
			// it is more than the Variable already shows: a wrapped call
			// (`memcpy(dst,\n  src,\n  n)`) is otherwise reduced to its first
			// line by the single-line Source column.
			if c.Expression != "" && c.Expression != c.Target.Variable {
				fmt.Fprintf(&b, "- **Expression:** `%s`\n", strings.ReplaceAll(c.Expression, "\n", " "))
			}
			b.WriteString("\n")

			// Embed the surrounding source so the classifier does not need a
			// separate source READ for a suspected/possible candidate. The same
			// window also appears in report.md's Source column for confirmed.
			if ctx := o.candidateContext(pkg.VulnerabilityType, c); ctx != nil {
				b.WriteString("## Code Context\n\n")
				fmt.Fprintf(&b, "`%s:%d-%d` — line %d is the reported location.\n\n", ctx.Path, ctx.StartLine, ctx.EndLine, ctx.Line)
				b.WriteString(ctx.render())
				b.WriteString("\n")
			} else {
				// An absent Code Context must be LOUD, not silent: the
				// classifier would otherwise mistake "no source shown" for
				// "no source semantics" and judge the candidate blind. The
				// usual cause is the file changing between scan and report
				// (line drift in a diff/incremental workflow).
				b.WriteString("## Code Context\n\n")
				fmt.Fprintf(&b, "- Source unavailable: `%s:%d` could not be read at report time (file changed or moved since the scan?).\n", c.Target.File, c.Target.Line)
				b.WriteString("- The Evidence fragments below are all the proof available for this candidate.\n\n")
			}

			// The taint origin statement, so the classifier never has to take
			// the fragment's word for it nor hunt for it inside the ±8 Code
			// Context window: the source is frequently farther from the sink
			// than the window reaches (that gap is E-05's whole point).
			if isTaintVulnType(pkg.VulnerabilityType) && c.SourceLine > 0 {
				if txt := sourceLineText(c.Target.File, c.SourceLine, o.RootDir); txt != "" {
					b.WriteString("## Taint Source\n\n")
					fmt.Fprintf(&b, "`%s:%d` — the user-controlled value originates here.\n\n", c.Target.File, c.SourceLine)
					fmt.Fprintf(&b, "```c\n%s\n```\n\n", txt)
				}
			}

			if pkg.VulnerabilityType == "unchecked-return" && c.Contract != "" {
				b.WriteString("## Failure Contract\n\n")
				if c.Contract == "known" {
					b.WriteString("- **Contract:** `known` — the callee is a standard unchecked-return API, a declared allocator, or a body-verified passthrough wrapper. An unchecked return is a genuine CWE-252 defect.\n\n")
				} else {
					b.WriteString("- **Contract:** `unknown` — the callee is an allocator by NAME only (an `alloc` substring, a `*_new`/`*_dup` factory). Its failure behaviour is unproven: it may be pool-, stack- or caller-buffer-backed and never fail. You must prove the callee returns a failure sentinel (NULL / -1 / error code) on the unchecked path, otherwise **dismiss**.\n\n")
					if c.CalleeDefFile != "" {
						sig := ""
						if c.CalleeDefSignature != "" {
							sig = fmt.Sprintf(" (`%s`)", c.CalleeDefSignature)
						}
						b.WriteString(fmt.Sprintf("- **Callee definition:** `%s:%d`%s\n\n", c.CalleeDefFile, c.CalleeDefLine, sig))
					} else {
						b.WriteString("- **Callee definition:** none in scan — the callee is external/library; prove its contract from API knowledge or dismiss\n\n")
					}
					// The proof burden is "does this callee return a failure
					// sentinel?", and every in-scan callee already has a body the
					// index located. Embedding it turns a source READ (a large
					// share of the classifier's read budget on this type) into
					// an in-file judgment.
					writeCalleeDefinition(&b, c, o, "the unchecked callee's body. Judge the failure sentinel from this body; no source read is needed.")
				}
			}
			// null-deref call-result dereferences (`f()->field`) and the variable
			// path whose malloc-fail origin is an in-scan callee (`p = f();
			// p->field`): the callee's body decides whether its return can be
			// NULL — the null@malloc-fail verdict fact names it, and the embedded
			// body settles it without a source read.
			if pkg.VulnerabilityType == "null-deref" && (c.IsCallResultDeref || (c.NullOriginTier == "malloc-fail" && c.CalleeDefFile != "")) {
				writeCalleeDefinition(&b, c, o, "the callee whose return is dereferenced. Judge whether its body can return NULL; no source read is needed.")
			}
			// double-free's conditional first-release helper (cond@<callee>): its
			// body decides whether the first release is conditional, so embed it
			// rather than sending the classifier on a whole-file source read to
			// find release_entry/cleanup_entries (round3 allocator.c:123).
			if pkg.VulnerabilityType == "double-free" && c.CalleeDefFile != "" {
				writeCalleeDefinition(&b, c, o, "the conditional first-release helper. Judge whether it frees only on some paths; no source read is needed.")
			}
			// The SECOND release helper (the unconditional cleanup call): its body
			// decides "both frees on one path" — embed it beside the first so the
			// classifier never reads the whole file to find cleanup_entries.
			if pkg.VulnerabilityType == "double-free" && c.SecondCalleeDefFile != "" {
				writeSecondCalleeDefinition(&b, c, o, "the second (unconditional cleanup) release helper. Judge whether it frees the slot again; no source read is needed.")
			}

			// The pipeline's verdict tokens with their registry descriptions, so
			// the candidate file is self-contained for RE-REVIEW and deep-dive:
			// the classifier that opens this file sees the same machine facts
			// the _index.md Hint column carried (previously the only place they
			// existed), each annotated with what it means — no legend lookup and
			// no re-derivation from the narrative fragments below.
			if len(c.HintTokens) > 0 {
				b.WriteString("## Pipeline Tokens\n\n")
				fmt.Fprintf(&b, "`%s`\n\n", strings.Join(c.HintTokens, " "))
				for _, tok := range c.HintTokens {
					b.WriteString(planner.DescribeHintToken(tok))
					b.WriteString("\n")
				}
				b.WriteString("\n")
			}

			// The type's decisive facts (Evidence Contract v2): each line is a
			// distilled semantic-graph ANSWER with provenance, elaborating the
			// token it names. Rendered only for types whose contract has rolled
			// out (BuildVerdictFacts); absent for types still on the fragment
			// narrative alone.
			if len(c.VerdictFacts) > 0 {
				b.WriteString("## Verdict Facts\n\n")
				for _, f := range c.VerdictFacts {
					if f.Token != "" {
						fmt.Fprintf(&b, "- `%s`: %s\n", f.Token, f.Detail)
					} else {
						fmt.Fprintf(&b, "- %s\n", f.Detail)
					}
				}
				b.WriteString("\n")
			}

			// The root-cause chain: one finding, two CWEs. Exported as its own
			// section (and as the `cwe-chain@` token / SARIF `cwe_chain`
			// property) so the classifier states the consequence without
			// inventing a duplicate finding for it.
			if c.CWEChain != "" {
				b.WriteString("## Vulnerability Chain\n\n")
				fmt.Fprintf(&b, "`%s` — the first CWE is the root cause and the fixable defect; the second is the consequence the verdict must name. Report ONE finding.\n\n", c.CWEChain)
			}

			b.WriteString("## Evidence\n\n")
			for _, e := range c.Evidence {
				label := e.Role
				if label == "" {
					label = e.Type
				}
				b.WriteString(fmt.Sprintf("- **%s:** %s\n", label, e.Detail))
			}
			b.WriteString("\n")

			b.WriteString("## Pipeline Assessment\n\n")
			b.WriteString(fmt.Sprintf("- **Suspicion Level (pipeline prior, not a verdict):** %s\n", c.SuspicionLevel))
			b.WriteString(fmt.Sprintf("- **AI Verdict:** _unclassified_\n"))
			b.WriteString("\n")

			b.WriteString("## Fix Suggestion\n\n")
			b.WriteString(FixSuggestion(pkg.VulnerabilityType, cwe, c))

			if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
				return err
			}
		}
	}
	return nil
}

// candidateContext resolves the Code Context region for one candidate.
// Most types read a ±candidateContextLines window around the reported line,
// but two span policies widen it:
//
//   - integer-overflow embeds the WHOLE function span (signature → candidate)
//     as command-instructions.md promises the classifier: its verdict needs the
//     parameter types, the entry guard and the accumulation chain, none of
//     which sit inside a ±8 window. A span longer than maxContextLines is
//     truncated from the signature; when the candidate falls outside that
//     truncated window the ±8 local window is used instead.
//
//   - a source→sink span (E-06): when a decisive source line (the free site of
//     a use-after-free, the two frees of a double-free, the uninit declaration,
//     the null/taint origin, the racing write) falls OUTSIDE the ±8 window, the
//     window widens to [min-3, max+3] over all decisive lines so the fragment's
//     "free(p) at line N" is checkable in view rather than trusted. A span
//     longer than maxContextLines stays on the local window — mostly padding,
//     and the fragment's line number still directs a targeted READ.
//
// An unknown span (0), a stale span, or a span the file cannot satisfy falls
// back to the local window, so behavior is unchanged for every other producer.
func (o *ScanOutput) candidateContext(vulnType string, c planner.EvidenceItem) *codeContext {
	local := func() *codeContext {
		return readCodeContext(c.Target.File, c.Target.Line, candidateContextLines, o.RootDir)
	}
	if vulnType == "integer-overflow" && c.FunctionStartLine > 0 && c.FunctionEndLine >= c.FunctionStartLine {
		start, end := c.FunctionStartLine, c.FunctionEndLine
		if end-start+1 > maxContextLines {
			end = start + maxContextLines - 1
		}
		if c.Target.Line >= start && c.Target.Line <= end {
			if ctx := readCodeSpan(c.Target.File, start, end, c.Target.Line, o.RootDir); ctx != nil {
				return ctx
			}
		}
		return local()
	}
	if lo, hi, ok := sourceSinkSpan(c); ok {
		if ctx := readCodeSpan(c.Target.File, lo, hi, c.Target.Line, o.RootDir); ctx != nil {
			return ctx
		}
	}
	return local()
}

// sourceSinkSpan returns the widened [lo, hi] window covering the reported
// line plus every decisive source line, and whether widening is warranted:
// only when at least one decisive line sits outside the ±candidateContextLines
// window (inside it the plain window already shows it), and only when the
// resulting span stays within maxContextLines.
func sourceSinkSpan(c planner.EvidenceItem) (int, int, bool) {
	if len(c.SourceLines) == 0 {
		return 0, 0, false
	}
	lo, hi := c.Target.Line, c.Target.Line
	outside := false
	for _, ln := range c.SourceLines {
		if ln < lo {
			lo = ln
		}
		if ln > hi {
			hi = ln
		}
		if ln < c.Target.Line-candidateContextLines || ln > c.Target.Line+candidateContextLines {
			outside = true
		}
	}
	if !outside {
		return 0, 0, false
	}
	lo -= 3
	if lo < 1 {
		lo = 1
	}
	hi += 3
	if hi-lo+1 > maxContextLines {
		return 0, 0, false
	}
	return lo, hi, true
}

// isTaintVulnType reports whether the type's candidates flow user-controlled
// data toward a sink, so a numbered taint origin (src@N) is meaningful for
// them. These are exactly the types the taint_source filter converges.
func isTaintVulnType(vulnType string) bool {
	return vulnType == "injection" || vulnType == "format-string" || vulnType == "path-traversal"
}

// maxCalleeDefLines caps the embedded callee body. A callee proving (or
// refuting) a NULL/-1/error sentinel is normally a short factory; the cap keeps
// one giant callee from turning a candidate file into a source dump.
const maxCalleeDefLines = 40

// calleeDefContext resolves the unchecked-return callee's definition body for
// embedding. The function index gives the exact span (StartLine-EndLine), so the
// body is usually complete; an unknown end line falls back to a bounded window
// from the definition's first line. A nil result means the file cannot be read
// writeCalleeDefinition embeds the callee's in-scan body under
// ## Callee Definition with a type-specific intro line. It is the shared
// embedding path for unchecked-return (failure-sentinel proof) and null-deref
// call-result dereferences (return-nullability proof); a callee with no
// definition in the scan (external/library) renders nothing — the token-level
// contract already says so.
func writeCalleeDefinition(b *strings.Builder, c planner.EvidenceItem, o *ScanOutput, intro string) {
	if c.CalleeDefFile == "" {
		return
	}
	if ctx := calleeDefContext(c, o.RootDir); ctx != nil {
		b.WriteString("## Callee Definition\n\n")
		fmt.Fprintf(b, "`%s:%d-%d` — %s\n\n", displayPath(c.CalleeDefFile, o.RootDir), ctx.StartLine, ctx.EndLine, intro)
		b.WriteString(ctx.render())
		if c.CalleeDefEndLine > ctx.EndLine {
			fmt.Fprintf(b, "\nBody truncated at line %d of %d — the callee continues past this window.\n", ctx.EndLine, c.CalleeDefEndLine)
		}
		b.WriteString("\n")
	} else {
		b.WriteString("## Callee Definition\n\n")
		fmt.Fprintf(b, "- Body unavailable at report time: `%s:%d` could not be read (file changed or moved since the scan?).\n- The callee is in the scan; read that location only if the signature above is insufficient.\n\n", displayPath(c.CalleeDefFile, o.RootDir), c.CalleeDefLine)
	}
}

// calleeDefContext locates the callee's definition body for embedding. The
// window is clamped to maxCalleeDefLines; the actual body span is preserved in
// the EvidenceItem so the truncation note stays honest. A body that cannot be
// read at report time, and the caller degrades to the location pointer.
func calleeDefContext(c planner.EvidenceItem, rootDir string) *codeContext {
	start := c.CalleeDefLine
	if start <= 0 {
		return nil
	}
	end := c.CalleeDefEndLine
	if end < start {
		end = start + maxCalleeDefLines - 1
	}
	if end-start+1 > maxCalleeDefLines {
		end = start + maxCalleeDefLines - 1
	}
	return readCodeSpan(c.CalleeDefFile, start, end, start, rootDir)
}

// writeSecondCalleeDefinition embeds the double-free SECOND release helper's
// body under ## Second Callee Definition, mirroring writeCalleeDefinition.
func writeSecondCalleeDefinition(b *strings.Builder, c planner.EvidenceItem, o *ScanOutput, intro string) {
	if c.SecondCalleeDefFile == "" {
		return
	}
	start := c.SecondCalleeDefLine
	if start <= 0 {
		return
	}
	end := c.SecondCalleeDefEndLine
	if end < start {
		end = start + maxCalleeDefLines - 1
	}
	if end-start+1 > maxCalleeDefLines {
		end = start + maxCalleeDefLines - 1
	}
	b.WriteString("## Second Callee Definition\n\n")
	if ctx := readCodeSpan(c.SecondCalleeDefFile, start, end, start, o.RootDir); ctx != nil {
		fmt.Fprintf(b, "`%s:%d-%d` — %s\n\n", displayPath(c.SecondCalleeDefFile, o.RootDir), ctx.StartLine, ctx.EndLine, intro)
		b.WriteString(ctx.render())
		if c.SecondCalleeDefEndLine > ctx.EndLine {
			fmt.Fprintf(b, "\nBody truncated at line %d of %d — the callee continues past this window.\n", ctx.EndLine, c.SecondCalleeDefEndLine)
		}
		b.WriteString("\n")
	} else {
		fmt.Fprintf(b, "- Body unavailable at report time: `%s:%d` could not be read.\n\n", displayPath(c.SecondCalleeDefFile, o.RootDir), c.SecondCalleeDefLine)
	}
}

// typeIndexLegend renders the _index.md header: the workflow framing (binary
// verdict, Source+Hint-first classification, evidence-open fallback) plus the
// token legend generated from the planner's hint token registry — the single
// source of truth for the vocabulary. It renders ONLY the registry entries the
// type's own emitted tokens use (HintLegendForTokens): the full-registry legend
// was ~60 lines of mostly-irrelevant tokens on every type's first read, which
// pushed the classifier to skim the Hint column instead of trusting it.
func typeIndexLegend(tokens []string) string {
	var b strings.Builder
	b.WriteString("> Classify each candidate as confirmed / dismissed (BINARY).\n")
	b.WriteString("> Classify from the `Source` + `Hint` columns first — `Hint` is the pipeline's\n")
	b.WriteString("> precomputed verdict facts (legend generated from the single source in\n")
	b.WriteString("> `sgre/internal/planner/hint_tokens.go`):\n>\n")
	for _, line := range planner.HintLegendForTokens(tokens) {
		b.WriteString("> ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString(">\n")
	b.WriteString("> Open the `Evidence` file (and its `## Code Context`) when the hint is\n")
	b.WriteString("> insufficient; read the source (≤5 turns per type) before dismissing\n")
	b.WriteString("> something you cannot settle.\n\n")
	return b.String()
}

// writeTypeIndex writes candidates/<vuln-type>/_index.md — the single table a
// subagent reads to classify ONE type (the # column matches the NNN candidate
// filenames, and the Source column carries the exact statement so the classifier
// never issues a per-candidate source READ). Splitting the index per type means
// a subagent assigned `null-deref` reads only its own slice, not every type's
// table in one monolithic report.md.
func (o *ScanOutput) writeTypeIndex(dir string, pkg *planner.PlanResult) error {
	cwe := VulnToCWE(pkg.VulnerabilityType)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# %s (%s) — Candidates\n\n", pkg.VulnerabilityType, cwe))
	// The legend is scoped to the tokens this type actually emitted (the union
	// across its candidates), so a subagent reads only its type's vocabulary.
	seen := make(map[string]bool)
	var legendTokens []string
	for _, c := range pkg.Candidates {
		for _, tok := range c.HintTokens {
			if !seen[tok] {
				seen[tok] = true
				legendTokens = append(legendTokens, tok)
			}
		}
	}
	b.WriteString(typeIndexLegend(legendTokens))
	b.WriteString("| # | Function | File:Line | Variable | Suspicion | Hint | Source | Evidence |\n")
	b.WriteString("|---|----------|-----------|----------|-----------|------|--------|----------|\n")
	for i, c := range pkg.Candidates {
		fileShort := displayPath(c.Target.File, o.RootDir)
		b.WriteString(fmt.Sprintf("| %d | %s | %s:%d | %s | %s | %s | %s | `%s` |\n",
			i+1, markdownCell(c.Target.Function), fileShort, c.Target.Line, markdownCell(c.Target.Variable), c.SuspicionLevel,
			markdownCell(c.Hint),
			markdownCell(sourceLineText(c.Target.File, c.Target.Line, o.RootDir)),
			candidateFilename(i+1, c.Target.File, c.Target.Line)))
	}
	return os.WriteFile(filepath.Join(dir, TypeIndexFile), []byte(b.String()), 0644)
}

// candidateFilename returns the on-disk candidate evidence filename for one
// candidate: <NNN>_<short-file>_<line>.md. It is shared by writeCandidates and
// writeTypeIndex so the index's Evidence column always names the exact file a
// subagent must open for the full Code Context.
func candidateFilename(seq int, filePath string, line int) string {
	return fmt.Sprintf("%03d_%s_%d.md", seq, sanitizeFilename(shortFile(filePath)), line)
}

func shortFile(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) <= 2 {
		return path
	}
	return strings.Join(parts[len(parts)-2:], "/")
}

func sanitizeFilename(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ".", "_")
	return s
}

// markdownCell escapes a source line so it can sit inside a markdown table cell:
// pipes are escaped, newlines collapsed, and the length capped so a pathological
// line (minified/generated code) cannot blow up report.md.
func markdownCell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "`", "'")
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}

func title(s string) string {
	words := strings.Split(s, "-")
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

// FixSuggestion returns a paste-ready remediation for a candidate, used both by
// the candidate evidence files and by the scan's auto-confirm pass (which turns
// a pipeline-proved candidate into an `auto-confirmed` finding, skipping the
// first-round AI classification).
func FixSuggestion(vulnType, cwe string, c planner.EvidenceItem) string {
	varName := c.Target.Variable
	if varName == "" {
		varName = "the variable"
	}
	funcName := c.Target.Function

	switch vulnType {
	case "null-deref":
		return fmt.Sprintf(
			"Add a NULL check before dereferencing `%s` in `%s`:\n\n"+
				"```c\n"+
				"if (%s == NULL) {\n"+
				"    // handle error: return, log, or assert\n"+
				"    return -1;\n"+
				"}\n"+
				"// safe to use %s here\n"+
				"```\n\n"+
				"Also ensure `%s` is properly initialized on all code paths leading to this point.\n",
			varName, funcName, varName, varName, varName)

	case "buffer-overflow":
		return fmt.Sprintf(
			"Validate the buffer size before accessing `%s` in `%s`:\n\n"+
				"```c\n"+
				"// Check bounds before write/read\n"+
				"if (offset + access_size > buffer_capacity) {\n"+
				"    return -1;  // or clamp the size\n"+
				"}\n"+
				"```\n\n"+
				"Prefer safe alternatives: `memcpy_s`, `strncpy_s`, `snprintf` instead of\n"+
				"`memcpy`, `strcpy`, `sprintf`. If using loop-based access, add an explicit\n"+
				"upper-bound check on the loop index.\n",
			varName, funcName)

	case "memory-leak":
		return fmt.Sprintf(
			"Ensure `%s` is freed on **all** code paths in `%s`, including error paths:\n\n"+
				"```c\n"+
				"char *%s = malloc(size);\n"+
				"if (!%s) return -1;\n"+
				"// ... use %s ...\n"+
				"free(%s);\n"+
				"%s = NULL;\n"+
				"return 0;\n"+
				"```\n\n"+
				"For complex control flow, use a `goto cleanup` pattern or RAII-style\n"+
				"create/destroy wrapper functions to guarantee release.\n",
			varName, funcName, varName, varName, varName, varName, varName)

	case "injection":
		checkText := strings.ToLower(c.Target.Variable)
		for _, e := range c.Evidence {
			checkText += " " + strings.ToLower(e.Detail)
		}
		if strings.Contains(checkText, "sql") || strings.Contains(checkText, "sqlite") ||
			strings.Contains(checkText, "query") {
			return fmt.Sprintf(
				"Use parameterized queries instead of string concatenation in `%s`:\n\n"+
					"```c\n"+
					"sqlite3_stmt *stmt;\n"+
					"sqlite3_prepare_v2(db, \"SELECT * FROM t WHERE id = ?\", -1, &stmt, NULL);\n"+
					"sqlite3_bind_text(stmt, 1, user_input, -1, SQLITE_STATIC);\n"+
					"sqlite3_step(stmt);\n"+
					"sqlite3_finalize(stmt);\n"+
					"```\n\n"+
					"Never interpolate user-controlled data into SQL query strings.\n",
				funcName)
		}
		return fmt.Sprintf(
			"Avoid passing user-controlled input to command execution functions in `%s`.\n\n"+
				"```c\n"+
				"// BAD:  system(user_input);\n"+
				"// GOOD: use execve() with explicit argument array\n"+
				"char *argv[] = {\"/bin/ls\", user_input, NULL};\n"+
				"execve(\"/bin/ls\", argv, NULL);\n"+
				"```\n\n"+
				"If shell invocation is unavoidable, strictly validate/whitelist the input\n"+
				"and escape shell metacharacters before use.\n",
			funcName)

	case "resource-leak":
		return fmt.Sprintf(
			"Ensure the resource acquired in `%s` is released on **all** code paths,\n"+
				"including error and early-return paths:\n\n"+
				"```c\n"+
				"FILE *f = fopen(path, \"r\");\n"+
				"if (!f) return -1;\n"+
				"// ... use f ...\n"+
				"fclose(f);\n"+
				"return 0;\n"+
				"```\n\n"+
				"For handles with create/destroy or acquire/release semantics, pair every\n"+
				"acquire with a matching release. Use `goto cleanup` for multi-resource\n"+
				"functions.\n",
			funcName)

	case "uninit":
		return fmt.Sprintf(
			"Initialize `%s` at declaration or ensure it is assigned before first use\n"+
				"in `%s`:\n\n"+
				"```c\n"+
				"// Option 1: initialize at declaration\n"+
				"int %s = 0;\n\n"+
				"// Option 2: explicit initialization before use\n"+
				"%s = compute_value();\n"+
				"if (error) return -1;\n"+
				"// now safe to use %s\n"+
				"```\n\n"+
				"For struct members, use `memset(&%s, 0, sizeof(%s))` or designated\n"+
				"initializers to zero-fill before use.\n",
			varName, funcName, varName, varName, varName, varName, varName)

	case "use-after-free":
		return fmt.Sprintf(
			"After freeing `%s` in `%s`, set the pointer to NULL to prevent\n"+
				"use-after-free:\n\n"+
				"```c\n"+
				"free(%s);\n"+
				"%s = NULL;  // prevents accidental reuse\n"+
				"```\n\n"+
				"Audit all code paths to ensure no aliasing pointer still references the\n"+
				"freed memory. Consider using a ownership-tracking wrapper or static analyzer\n"+
				"to enforce lifetime discipline.\n",
			varName, funcName, varName, varName)

	case "double-free":
		return fmt.Sprintf(
			"Prevent double-free of `%s` in `%s` by setting the pointer to NULL\n"+
				"after the first free:\n\n"+
				"```c\n"+
				"free(%s);\n"+
				"%s = NULL;  // subsequent free(NULL) is a safe no-op\n"+
				"```\n\n"+
				"For complex ownership, track the allocation state explicitly with a flag\n"+
				"or use a wrapper that checks `if (ptr != NULL)` before freeing.\n",
			varName, funcName, varName, varName)

	case "format-string":
		return fmt.Sprintf(
			"Use a constant format string in `%s`; never let user input be the format\n"+
				"argument:\n\n"+
				"```c\n"+
				"// BAD:  printf(user_input);\n"+
				"// GOOD: printf(\"%%s\", user_input);\n"+
				"```\n\n"+
				"If dynamic formatting is needed, use `vsnprintf` with a fixed-size buffer\n"+
				"and a caller-specified format string that is validated against a whitelist.\n",
			funcName)

	case "integer-overflow":
		switch c.Category {
		case "unsigned_sub_underflow":
			return fmt.Sprintf(
				"Guard the unsigned subtraction before it can underflow in `%s`:\n\n"+
					"```c\n"+
					"// Before `total - consumed`, prove the invariant consumed <= total\n"+
					"if (consumed > total) {\n"+
					"    return -1;  // or clamp/validate the inputs\n"+
					"}\n"+
					"size_t remaining = total - consumed;  // safe: consumed <= total\n"+
					"```\n\n"+
					"Ensure `%s` never exceeds its upper bound: either validate both\n"+
					"operands at entry, or make every accumulator (`length += f(...)`)\n"+
					"a truncating call whose return value stays within the remaining space.\n",
				funcName, c.Target.Variable)

		case "size_calc_overflow", "size_mul_const_overflow":
			return fmt.Sprintf(
				"Check the multiplication before allocating in `%s`:\n\n"+
					"```c\n"+
					"// Before count * elem_size, prove it cannot wrap\n"+
					"if (count > SIZE_MAX / elem_size) {\n"+
					"    return NULL;  // overflow would occur\n"+
					"}\n"+
					"size_t total = count * elem_size;\n"+
					"char *buf = malloc(total);\n"+
					"```\n\n"+
					"Use `size_t` for sizes (never `int`) and prefer checked arithmetic\n"+
					"(`__builtin_mul_overflow`) or a checked-allocation wrapper.\n",
				funcName)

		default:
			return fmt.Sprintf(
				"Check for integer overflow before using the result in `%s`:\n\n"+
					"```c\n"+
					"if (a > INT_MAX - b) {\n"+
					"    return -1;  // overflow would occur\n"+
					"}\n"+
					"int total = a + b;\n"+
					"```\n\n"+
					"Use a wide-enough type for the operation and prefer\n"+
					"`__builtin_add_overflow`/`__builtin_mul_overflow` for checked arithmetic.\n",
				funcName)
		}

	case "race-condition":
		return fmt.Sprintf(
			"Eliminate the time-of-check-to-time-of-use (TOCTOU) race in `%s` by\n"+
				"performing check and use atomically:\n\n"+
				"```c\n"+
				"// BAD: if (access(path, R_OK) == 0) { f = fopen(path, \"r\"); }\n"+
				"// GOOD: open the file directly and check the fd\n"+
				"int fd = open(path, O_RDONLY);\n"+
				"if (fd < 0) { /* handle */ }\n"+
				"FILE *f = fdopen(fd, \"r\");\n"+
				"```\n\n"+
				"For shared state, protect check-then-act sequences with a mutex:\n"+
				"lock before the check and hold the lock through the mutation. Avoid\n"+
				"`access()` + `fopen()` patterns; use `fopen()` and check the result.\n",
			funcName)

	case "hardcoded-secret":
		return fmt.Sprintf(
			"Remove the hardcoded credential from `%s` and load it from a secure\n"+
				"source at runtime:\n\n"+
				"```c\n"+
				"// BAD:  const char *password = \"admin123\";\n"+
				"// GOOD: read from env var, vault, or config file with restricted perms\n"+
				"const char *password = getenv(\"APP_PASSWORD\");\n"+
				"if (!password) { return -1; }\n"+
				"```\n\n"+
				"Store secrets in a secrets manager (HashiCorp Vault, cloud KMS) or a\n"+
				"file with `0600` permissions outside the repo. Never commit credentials\n"+
				"to source control. Rotate any credentials that were previously hardcoded.\n",
			funcName)

	case "deadlock":
		return fmt.Sprintf(
			"Eliminate the lock-order inversion in `%s` by establishing a consistent\n"+
				"global lock acquisition order:\n\n"+
				"```c\n"+
				"// Rule: always acquire lockA before lockB\n"+
				"pthread_mutex_lock(&lockA);\n"+
				"pthread_mutex_lock(&lockB);\n"+
				"// ... critical section ...\n"+
				"pthread_mutex_unlock(&lockB);\n"+
				"pthread_mutex_unlock(&lockA);\n"+
				"```\n\n"+
				"Document the lock hierarchy and enforce it with static analysis or\n"+
				"runtime lock-order sanitizers (e.g., TSan). Consider using a single\n"+
				"coarse-grained lock if the ordering is hard to maintain, or refactor\n"+
				"to avoid nested locking.\n",
			funcName)

	case "crypto-misuse":
		return fmt.Sprintf(
			"Replace the weak cryptographic primitive in `%s` with a modern,\n"+
				"industry-standard alternative:\n\n"+
				"```c\n"+
				"// BAD:  DES_set_key_unchecked(&key, &schedule);\n"+
				"// GOOD: use AES-256 via a vetted library (OpenSSL EVP)\n"+
				"EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();\n"+
				"EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);\n"+
				"```\n\n"+
				"Specific replacements: DES/3DES → AES-256; MD5/SHA1 → SHA-256 or SHA-3;\n"+
				"rand() → cryptographic PRNG (getrandom, CryptGenRandom); RC4 → AES.\n"+
				"Use keys of at least 128 bits (256 recommended for long-term security).\n",
			funcName)

	case "path-traversal":
		return fmt.Sprintf(
			"Validate and constrain the path before the filesystem call in `%s`:\n\n"+
				"```c\n"+
				"// 1. Reject absolute paths and any '..' component\n"+
				"if (path[0] == '/' || strstr(path, \"..\") != NULL) {\n"+
				"    return -1;  // or reject the request\n"+
				"}\n"+
				"// 2. Build the path under a fixed base directory\n"+
				"char safe[PATH_MAX];\n"+
				"snprintf(safe, sizeof(safe), \"%%s/%%s\", BASE_DIR, path);\n"+
				"// 3. Canonicalize and verify the real path stays inside BASE_DIR\n"+
				"char resolved[PATH_MAX];\n"+
				"if (realpath(safe, resolved) == NULL) return -1;\n"+
				"if (strncmp(resolved, BASE_DIR, strlen(BASE_DIR)) != 0) return -1;\n"+
				"// 4. Only now touch the filesystem\n"+
				"FILE *f = fopen(resolved, \"r\");\n"+
				"```\n\n"+
				"Never pass an unvalidated caller-controlled path directly to a filesystem\n"+
				"call. The canonical check is: reject `..`/absolute paths, resolve with\n"+
				"realpath, and confirm the result still lives inside the allowed base dir.\n",
			funcName)

	default:
		return "Review the evidence above and apply the appropriate mitigation for this\n" +
			"vulnerability class. Consult the CWE documentation for detailed guidance.\n"
	}
}
