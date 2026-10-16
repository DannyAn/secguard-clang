package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

func candidatePackages() []*planner.PlanResult {
	return []*planner.PlanResult{{
		VulnerabilityType: "null-deref",
		Candidates: []planner.EvidenceItem{{
			SuspicionLevel: "confirmed",
			Target: planner.TargetInfo{
				File: "/repo/src/a.c", Function: "f", Line: 13, Variable: "p",
			},
			Evidence: []planner.EvidenceFragment{
				{Role: "source", Detail: "p assigned a possibly-null value"},
			},
		}},
	}}
}

// The candidate stage must not look like a verdict: a file that says
// "Suspicion Level: confirmed" next to "Status: pending" made reviewers read a
// pipeline prior as an AI conclusion.
func TestWriteCandidates_NoVerdictLanguage(t *testing.T) {
	dir := t.TempDir()
	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test"}
	if err := o.writeCandidates(candidatePackages()); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, CandidatesDir, "null-deref", "001_src_a_c_13.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("candidate evidence should live under %s/: %v", CandidatesDir, err)
	}
	content := string(data)

	if strings.Contains(content, "**Status:**") {
		t.Errorf("candidate file must not carry a Status line (it has no verdict):\n%s", content)
	}
	if strings.Contains(content, "_pending_") {
		t.Errorf("candidate file must not claim a pending verdict:\n%s", content)
	}
	if !strings.Contains(content, "pipeline prior, not a verdict") {
		t.Errorf("suspicion level must be labelled as a pipeline prior:\n%s", content)
	}
	if !strings.Contains(content, "- **AI Verdict:** _unclassified_") {
		t.Errorf("candidate file should state that no AI verdict exists yet:\n%s", content)
	}
	if _, err := os.Stat(filepath.Join(dir, FindingsDir)); !os.IsNotExist(err) {
		t.Errorf("%s/ must stay empty until the AI classifies (err=%v)", FindingsDir, err)
	}
}

func TestWriteReport_DocumentsBothDirs(t *testing.T) {
	dir := t.TempDir()
	o := &ScanOutput{
		ScanDir:    dir,
		ScanID:     "sc_test",
		ReportPath: filepath.Join(dir, ReportFile),
		SarifPath:  filepath.Join(dir, SarifFile),
	}
	if err := o.writeReport(candidatePackages(), IndexSummary{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(o.ReportPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, want := range []string{CandidatesDir + "/<vuln-type>/", FindingsDir + "/<vuln-type>/", "Dismissed"} {
		if !strings.Contains(content, want) {
			t.Errorf("report.md should explain %q:\n%s", want, content)
		}
	}
}

func verdictFindings() []*db.Finding {
	return []*db.Finding{
		{
			RuleID: "CWE-787", Severity: "high", Confidence: 0.9,
			Status: "confirmed", ReviewStatus: "",
			FilePath: "src/overflow.c", LineNumber: 42, FunctionName: "vuln_write",
			Summary: "栈缓冲区溢出", Reasoning: "memcpy 长度超过缓冲区容量",
		},
		{
			RuleID: "CWE-787", Severity: "medium", Confidence: 0.6,
			Status: "suspected", ReviewStatus: "suspected-kept",
			FilePath: "src/maybe.c", LineNumber: 17, FunctionName: "risky_copy",
			Summary: "可能溢出", Reasoning: "长度依赖外部输入",
		},
		{
			RuleID: "CWE-787", Severity: "low", Confidence: 0.3,
			Status: "suspected", ReviewStatus: "dismissed",
			FilePath: "src/false.c", LineNumber: 8, FunctionName: "safe_check",
			Summary: "误报", Reasoning: "已有边界检查",
		},
		{
			RuleID: "CWE-416", Severity: "high", Confidence: 0.85,
			Status: "confirmed", ReviewStatus: "",
			FilePath: "src/uaf.c", LineNumber: 99, FunctionName: "dangling",
			Summary: "释放后使用", Reasoning: "free 后仍访问指针",
		},
	}
}

// WriteReportFromFindings must show only CONFIRMED findings and must never
// include dismissed or suspected entries — mirroring result.sarif and the
// findings/ directory (suspected live in suspected.sarif).
func TestWriteReportFromFindings_ExcludesDismissed(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, ReportFile)

	if err := WriteReportFromFindings(reportPath, "", verdictFindings(), ScanOverview{}); err != nil {
		t.Fatalf("WriteReportFromFindings: %v", err)
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if strings.Contains(content, "safe_check") {
		t.Errorf("dismissed finding must not appear in report.md:\n%s", content)
	}
	if strings.Contains(content, "误报") {
		t.Errorf("dismissed finding summary must not appear in report.md:\n%s", content)
	}
}

func TestWriteReportFromFindings_ShowsActionable(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, ReportFile)

	if err := WriteReportFromFindings(reportPath, "", verdictFindings(), ScanOverview{}); err != nil {
		t.Fatalf("WriteReportFromFindings: %v", err)
	}

	content := string(mustReadFile(t, reportPath))

	for _, want := range []string{"vuln_write", "dangling"} {
		if !strings.Contains(content, want) {
			t.Errorf("confirmed finding %q should appear in report.md:\n%s", want, content)
		}
	}
	if strings.Contains(content, "risky_copy") {
		t.Errorf("suspected finding must NOT appear in report.md (not a confirmed defect):\n%s", content)
	}
	if !strings.Contains(content, "AI-classified confirmed findings") {
		t.Errorf("report should declare it shows AI-classified confirmed findings:\n%s", content)
	}
	if !strings.Contains(content, "| Confirmed findings | 2 |") {
		t.Errorf("summary should count 2 confirmed:\n%s", content)
	}
	if strings.Contains(content, "Suspected findings") {
		t.Errorf("summary must not render a Suspected findings row (binary verdict):\n%s", content)
	}
	if strings.Contains(content, "| Dismissed |") {
		t.Errorf("summary must not render a Dismissed row (dismissed not persisted):\n%s", content)
	}
}

// A suspected finding (plain or suspected-kept) is not a confirmed defect: it
// must NOT appear in the user-facing report.md.
func TestWriteReportFromFindings_IncludesPlainSuspected(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, ReportFile)

	findings := []*db.Finding{
		{
			RuleID: "CWE-787", Severity: "medium", Confidence: 0.6,
			Status: "suspected", ReviewStatus: "",
			FilePath: "src/maybe.c", LineNumber: 17, FunctionName: "risky_copy",
			Summary: "可能溢出", Reasoning: "长度依赖外部输入",
		},
		{
			RuleID: "CWE-787", Severity: "medium", Confidence: 0.6,
			Status: "suspected", ReviewStatus: "suspected-kept",
			FilePath: "src/kept.c", LineNumber: 20, FunctionName: "kept_risky",
			Summary: "A5 保留的疑似", Reasoning: "外部输入无界",
		},
	}

	if err := WriteReportFromFindings(reportPath, "", findings, ScanOverview{}); err != nil {
		t.Fatalf("WriteReportFromFindings: %v", err)
	}

	content := string(mustReadFile(t, reportPath))

	if strings.Contains(content, "risky_copy") || strings.Contains(content, "kept_risky") {
		t.Errorf("suspected findings must NOT appear in report.md (not confirmed defects):\n%s", content)
	}
	if strings.Contains(content, "Suspected findings") {
		t.Errorf("summary must not render a Suspected findings row (binary verdict):\n%s", content)
	}
}

func TestWriteReportFromFindings_GroupsByVulnType(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, ReportFile)

	if err := WriteReportFromFindings(reportPath, "", verdictFindings(), ScanOverview{}); err != nil {
		t.Fatalf("WriteReportFromFindings: %v", err)
	}

	content := string(mustReadFile(t, reportPath))

	if !strings.Contains(content, "## buffer-overflow") {
		t.Errorf("should have a buffer-overflow section:\n%s", content)
	}
	if !strings.Contains(content, "## use-after-free") {
		t.Errorf("should have a use-after-free section:\n%s", content)
	}
}

func TestWriteReportFromFindings_EmptyFindings(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, ReportFile)

	if err := WriteReportFromFindings(reportPath, "", nil, ScanOverview{}); err != nil {
		t.Fatalf("WriteReportFromFindings with nil findings: %v", err)
	}

	content := string(mustReadFile(t, reportPath))
	if !strings.Contains(content, "| Confirmed findings | 0 |") {
		t.Errorf("empty findings should produce zero counts:\n%s", content)
	}
}

func TestWriteReportFromFindings_RespectsReviewStatus(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, ReportFile)

	findings := []*db.Finding{
		{
			RuleID: "CWE-476", Severity: "high", Confidence: 0.8,
			Status: "confirmed", ReviewStatus: "dismissed",
			FilePath: "src/a.c", LineNumber: 5, FunctionName: "f",
			Summary: "A5 降级为误报",
		},
	}

	if err := WriteReportFromFindings(reportPath, "", findings, ScanOverview{}); err != nil {
		t.Fatalf("WriteReportFromFindings: %v", err)
	}

	content := string(mustReadFile(t, reportPath))
	if strings.Contains(content, "| Confirmed findings | 1 |") {
		t.Errorf("A5 review_status=dismissed must override first-pass confirmed:\n%s", content)
	}
	if strings.Contains(content, "| Dismissed |") {
		t.Errorf("summary must not render a Dismissed row (dismissed not persisted):\n%s", content)
	}
}

// The per-type _index.md must name the EXACT candidate evidence filename in its
// Evidence column, so a subagent can open a suspected/possible candidate's
// Code Context without guessing the <NNN>_<short-file>_<line>.md name.
func TestWriteTypeIndex_IncludesEvidenceFilename(t *testing.T) {
	dir := t.TempDir()
	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test", RootDir: "/repo"}
	if err := o.writeCandidates(candidatePackages()); err != nil {
		t.Fatal(err)
	}

	idxPath := filepath.Join(dir, CandidatesDir, "null-deref", TypeIndexFile)
	content := string(mustReadFile(t, idxPath))

	for _, want := range []string{"| Evidence |", "001_src_a_c_13.md"} {
		if !strings.Contains(content, want) {
			t.Errorf("_index.md missing %q:\n%s", want, content)
		}
	}
	// The candidate file named by Evidence must actually exist on disk.
	if _, err := os.Stat(filepath.Join(dir, CandidatesDir, "null-deref", "001_src_a_c_13.md")); err != nil {
		t.Errorf("evidence file named by _index.md does not exist: %v", err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// integer-overflow evidence files must carry the function signature (operand
// types) so the classifier can read them without a source READ, while keeping the
// same ±N Code Context window as every other type.
func TestWriteCandidates_IntegerOverflowSignature(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "buf.c")
	body := "uint32_t grow(uint32_t n);\n" +
		"uint32_t f(uint32_t buf_len, uint32_t x) {\n" +
		"    uint32_t length = 0;\n" +
		"    length += grow(1);\n" +
		"    use(buf_len - length);\n" +
		"    return length;\n" +
		"}\n"
	if err := os.WriteFile(src, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}

	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test", RootDir: dir}
	pkgs := []*planner.PlanResult{{
		VulnerabilityType: "integer-overflow",
		Candidates: []planner.EvidenceItem{{
			SuspicionLevel: "suspected",
			Category:       "unsigned_sub_underflow",
			Hint:           "guard@none cat@unsigned_sub_underflow",
			Signature:      "f(uint32_t buf_len, uint32_t x)",
			Target: planner.TargetInfo{
				File: "buf.c", Function: "f", Line: 5, Variable: "buf_len - length",
			},
			Evidence: []planner.EvidenceFragment{
				{Role: "sink", Detail: "unsigned subtraction can underflow"},
			},
		}},
	}}
	if err := o.writeCandidates(pkgs); err != nil {
		t.Fatal(err)
	}

	content := string(mustReadFile(t, filepath.Join(dir, CandidatesDir, "integer-overflow", "001_buf_c_5.md")))
	if !strings.Contains(content, "- **Signature:** `f(uint32_t buf_len, uint32_t x)`") {
		t.Errorf("integer-overflow evidence should embed the function signature:\n%s", content)
	}
}

// E-01 regression: integer-overflow candidates embed the WHOLE function span
// (signature → candidate) in Code Context — the promise command-instructions.md
// makes to the classifier — instead of the ±8 local window. A candidate whose
// span is unknown (0) keeps the ±8 window, so every other producer is unchanged.
func TestWriteCandidates_IntegerOverflowFunctionSpan(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "span.c")
	var lines []string
	lines = append(lines, "#include <stdlib.h>", "")
	lines = append(lines, "static unsigned int process(unsigned int r) { return r; }", "")
	funcStart := len(lines) + 1
	lines = append(lines, "int f(unsigned int total, unsigned int consumed) {")
	for i := 0; i < 14; i++ {
		lines = append(lines, fmt.Sprintf("    acc%d = %d;", i, i))
	}
	candLine := len(lines) + 1
	lines = append(lines, "    process(total - consumed);")
	lines = append(lines, "    return 0;", "}")
	funcEnd := len(lines)
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(src, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}

	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test", RootDir: dir}
	spanPkg := &planner.PlanResult{
		VulnerabilityType: "integer-overflow",
		Candidates: []planner.EvidenceItem{{
			SuspicionLevel:    "suspected",
			Category:          "unsigned_sub_underflow",
			FunctionStartLine: funcStart,
			FunctionEndLine:   funcEnd,
			Target:            planner.TargetInfo{File: "span.c", Function: "f", Line: candLine},
		}},
	}
	if err := o.writeCandidates([]*planner.PlanResult{spanPkg}); err != nil {
		t.Fatal(err)
	}

	content := string(mustReadFile(t, filepath.Join(dir, CandidatesDir, "integer-overflow", "001_span_c_"+strconv.Itoa(candLine)+".md")))
	if !strings.Contains(content, fmt.Sprintf("`%s:%d-%d`", src, funcStart, funcEnd)) {
		t.Errorf("integer-overflow Code Context should embed the whole function span [%d,%d]:\n%s", funcStart, funcEnd, content)
	}
	if !strings.Contains(content, fmt.Sprintf("%d | int f(unsigned int total, unsigned int consumed) {", funcStart)) {
		t.Errorf("integer-overflow Code Context should include the signature line %d:\n%s", funcStart, content)
	}
	if !strings.Contains(content, fmt.Sprintf("> %d |     process(total - consumed);", candLine)) {
		t.Errorf("integer-overflow Code Context should mark the candidate line %d:\n%s", candLine, content)
	}
}

// E-01 regression, fallback half: a candidate whose line falls outside its
// recorded span (stale index) or whose span exceeds maxContextLines with the
// candidate beyond the truncated window keeps the ±8 local window, so the
// reported statement is always visible.
func TestWriteCandidates_IntegerOverflowSpanFallback(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "fallback.c")
	var lines []string
	lines = append(lines, "#include <stdlib.h>", "")
	lines = append(lines, "int g(unsigned int a, unsigned int b) {")
	candLine := len(lines) + 1
	lines = append(lines, "    process(a - b);")
	lines = append(lines, "    return 0;", "}")
	totalLines := len(lines)
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(src, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}

	// A >maxContextLines function span whose candidate sits at line 204: the
	// span truncates to [1,200] from the signature, so the candidate falls
	// outside and must fall back to the ±8 window.
	srcLong := filepath.Join(dir, "overlong.c")
	var longLines []string
	longLines = append(longLines, "#include <stdlib.h>")
	for i := 0; i < 202; i++ {
		longLines = append(longLines, "    int pad;")
	}
	longCand := len(longLines) + 1
	longLines = append(longLines, "    process(a - b);")
	longLines = append(longLines, "    return 0;", "}")
	longTotal := len(longLines)
	if err := os.WriteFile(srcLong, []byte(strings.Join(longLines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test", RootDir: dir}
	mk := func(file string, line, spanStart, spanEnd int) planner.EvidenceItem {
		return planner.EvidenceItem{
			SuspicionLevel:    "suspected",
			Category:          "unsigned_sub_underflow",
			FunctionStartLine: spanStart,
			FunctionEndLine:   spanEnd,
			Target:            planner.TargetInfo{File: file, Function: "g", Line: line},
		}
	}
	// stale span: candidate line is outside [start,end] entirely
	stale := mk("fallback.c", candLine, candLine+50, candLine+60)
	// over-long span: candidate beyond the truncated [1,200] window
	overlong := mk("overlong.c", longCand, 1, 300)
	pkgs := []*planner.PlanResult{{
		VulnerabilityType: "integer-overflow",
		Candidates:        []planner.EvidenceItem{stale, overlong},
	}}
	if err := o.writeCandidates(pkgs); err != nil {
		t.Fatal(err)
	}

	checkWindow := func(name string, file string, line, total int) {
		t.Helper()
		content := string(mustReadFile(t, filepath.Join(dir, CandidatesDir, "integer-overflow", name)))
		wantStart, wantEnd := line-8, line+8
		if wantStart < 1 {
			wantStart = 1
		}
		if wantEnd > total {
			wantEnd = total
		}
		if !strings.Contains(content, fmt.Sprintf("`%s:%d-%d`", file, wantStart, wantEnd)) {
			t.Errorf("%s with unusable span should fall back to the ±8 window [%d,%d]:\n%s", name, wantStart, wantEnd, content)
		}
	}
	checkWindow(fmt.Sprintf("001_fallback_c_%d.md", candLine), src, candLine, totalLines)
	checkWindow(fmt.Sprintf("002_overlong_c_%d.md", longCand), srcLong, longCand, longTotal)
}

// E-03 regression: the Failure Contract section of a contract@unknown
// unchecked-return candidate file must carry the callee's definition location
// (the callee is typically defined in another file) or the explicit
// "none in scan" for external callees, so the classifier never burns source
// READs locating a body the index already knows about.
func TestWriteCandidates_UncheckedReturnCalleeDefinition(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "call.c")
	body := "int handle(void) {\n    obj_pool_new(1);\n    return 0;\n}\n\nint handle_ext(void) {\n    ext_buf_dup(s);\n    return 0;\n}\n"
	if err := os.WriteFile(src, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}

	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test", RootDir: dir}
	pkgs := []*planner.PlanResult{{
		VulnerabilityType: "unchecked-return",
		Candidates: []planner.EvidenceItem{
			{
				SuspicionLevel:     "suspected",
				Category:           "unchecked_return",
				Contract:           "unknown",
				CalleeDefFile:      "pool.c",
				CalleeDefLine:      42,
				CalleeDefSignature: "Obj *obj_pool_new(int n)",
				Target:             planner.TargetInfo{File: "call.c", Function: "handle", Line: 2},
			},
			{
				SuspicionLevel: "suspected",
				Category:       "unchecked_return",
				Contract:       "unknown",
				Target:         planner.TargetInfo{File: "call.c", Function: "handle_ext", Line: 6},
			},
		},
	}}
	if err := o.writeCandidates(pkgs); err != nil {
		t.Fatal(err)
	}

	def := string(mustReadFile(t, filepath.Join(dir, CandidatesDir, "unchecked-return", "001_call_c_2.md")))
	if !strings.Contains(def, "- **Callee definition:** `pool.c:42` (`Obj *obj_pool_new(int n)`)") {
		t.Errorf("in-scan callee must render the definition location:\n%s", def)
	}
	ext := string(mustReadFile(t, filepath.Join(dir, CandidatesDir, "unchecked-return", "002_call_c_6.md")))
	if !strings.Contains(ext, "none in scan") {
		t.Errorf("external callee must render the explicit no-definition note:\n%s", ext)
	}
}

// FixSuggestion must branch integer-overflow by category: the dominant
// unsigned_sub_underflow pattern is a subtraction guard, not a malloc product.
func TestFixSuggestion_IntegerOverflowPerCategory(t *testing.T) {
	underflow := FixSuggestion("integer-overflow", "CWE-190", planner.EvidenceItem{
		Category: "unsigned_sub_underflow",
		Target:   planner.TargetInfo{Variable: "buf_len - length", Function: "f"},
	})
	if strings.Contains(underflow, "SIZE_MAX / elem_size") || strings.Contains(underflow, "malloc(total)") {
		t.Errorf("unsigned_sub_underflow fix suggestion must not be the malloc template:\n%s", underflow)
	}
	if !strings.Contains(underflow, "consumed > total") {
		t.Errorf("unsigned_sub_underflow fix suggestion should show the subtraction guard:\n%s", underflow)
	}

	sizeCalc := FixSuggestion("integer-overflow", "CWE-190", planner.EvidenceItem{
		Category: "size_calc_overflow",
		Target:   planner.TargetInfo{Variable: "count * elem_size", Function: "g"},
	})
	if !strings.Contains(sizeCalc, "SIZE_MAX / elem_size") {
		t.Errorf("size_calc_overflow fix suggestion should show the multiply check:\n%s", sizeCalc)
	}
}

// E-05 regression: a taint candidate whose source is more than ±8 lines from
// the sink gets the origin statement rendered in its own section — the Code
// Context window cannot contain it, so this section is the only in-file view
// of the taint origin the classifier needs.
func TestWriteCandidates_TaintSourceSection(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "taint.c")
	body := "int distant(void) {\n    char *env = getenv(\"USER\");\n    char *p = env;\n    FILE *f = fopen(p, \"r\");\n    return f != 0;\n}\n"
	if err := os.WriteFile(src, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}

	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test", RootDir: dir}
	pkgs := []*planner.PlanResult{{
		VulnerabilityType: "path-traversal",
		Candidates: []planner.EvidenceItem{{
			SuspicionLevel: "suspected",
			Category:       "path_traversal",
			SourceLine:     2,
			Target:         planner.TargetInfo{File: "taint.c", Function: "distant", Line: 4},
		}},
	}}
	if err := o.writeCandidates(pkgs); err != nil {
		t.Fatal(err)
	}

	content := string(mustReadFile(t, filepath.Join(dir, CandidatesDir, "path-traversal", "001_taint_c_4.md")))
	if !strings.Contains(content, "## Taint Source") {
		t.Errorf("candidate file must carry a Taint Source section:\n%s", content)
	}
	if !strings.Contains(content, "`taint.c:2`") {
		t.Errorf("Taint Source section must locate the origin line:\n%s", content)
	}
	if !strings.Contains(content, "getenv(\"USER\")") {
		t.Errorf("Taint Source section must carry the origin statement text:\n%s", content)
	}
}
