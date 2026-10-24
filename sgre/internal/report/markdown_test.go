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
	// The callee body lives in ANOTHER file: the candidate must embed it so the
	// contract@unknown proof ("does it return a failure sentinel?") is an
	// in-file judgment, not a source READ.
	pool := filepath.Join(dir, "pool.c")
	poolBody := "/* pad */\n\nObj *obj_pool_new(int n) {\n    if (n <= 0) return NULL;\n    Obj *o = calloc(1, sizeof(*o));\n    if (!o) return NULL;\n    return o;\n}\n"
	if err := os.WriteFile(pool, []byte(poolBody), 0644); err != nil {
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
				CalleeDefLine:      3,
				CalleeDefEndLine:   8,
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
	if !strings.Contains(def, "- **Callee definition:** `pool.c:3` (`Obj *obj_pool_new(int n)`)") {
		t.Errorf("in-scan callee must render the definition location:\n%s", def)
	}
	if !strings.Contains(def, "## Callee Definition") || !strings.Contains(def, "if (n <= 0) return NULL;") {
		t.Errorf("in-scan callee body must be embedded:\n%s", def)
	}
	if strings.Contains(def, "read the definition") {
		t.Errorf("evidence must not send the classifier on a source READ once the body is embedded:\n%s", def)
	}
	ext := string(mustReadFile(t, filepath.Join(dir, CandidatesDir, "unchecked-return", "002_call_c_6.md")))
	if !strings.Contains(ext, "none in scan") {
		t.Errorf("external callee must render the explicit no-definition note:\n%s", ext)
	}
	if strings.Contains(ext, "## Callee Definition") {
		t.Errorf("an external callee has no body and must not get a Callee Definition section:\n%s", ext)
	}
}

// P1-5: the callee-body embedding is driven by CalleeDefFile, not a hardcoded
// type list — a type WITHOUT a dedicated intro (here data-representation, whose
// comparator body decides the verdict) still embeds the in-scan callee body as a
// related Code Context path segment.
func TestWriteCandidates_GenericCalleeDefinition(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "use.c")
	if err := os.WriteFile(src, []byte("int use(void) { return cmp_fn(1); }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cmp := filepath.Join(dir, "cmp.c")
	cmpBody := "/* pad */\nint cmp_fn(int a) {\n    return a > 0;\n}\n"
	if err := os.WriteFile(cmp, []byte(cmpBody), 0644); err != nil {
		t.Fatal(err)
	}

	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test", RootDir: dir}
	pkgs := []*planner.PlanResult{{
		VulnerabilityType: "data-representation",
		Candidates: []planner.EvidenceItem{{
			SuspicionLevel:   "suspected",
			Category:         "data_representation_mismatch",
			CalleeDefFile:    "cmp.c",
			CalleeDefLine:    2,
			CalleeDefEndLine: 4,
			Target:           planner.TargetInfo{File: "use.c", Function: "use", Line: 1},
		}},
	}}
	if err := o.writeCandidates(pkgs); err != nil {
		t.Fatal(err)
	}

	def := string(mustReadFile(t, filepath.Join(dir, CandidatesDir, "data-representation", "001_use_c_1.md")))
	if !strings.Contains(def, "## Callee Definition") || !strings.Contains(def, "int cmp_fn(int a)") {
		t.Errorf("a non-hardcoded type with an in-scan callee must embed its body:\n%s", def)
	}
}

// NC-06: when the source→sink span exceeds maxContextLines the window falls
// back to ±8 — but the decisive source line then sits OUTSIDE the shown
// window with no visible note. The classifier must be told the window was
// truncated and which line to read directly.
func TestWriteCandidates_SourceSinkSpanTruncationNote(t *testing.T) {
	dir := t.TempDir()
	// Build a 250-line function: malloc at line 5, deref at line 250.
	var sb strings.Builder
	sb.WriteString("#include <stdlib.h>\ntypedef struct { int x; } T;\n\nT *f(void) {\n    T *p = malloc(sizeof(T));\n")
	for i := 6; i < 250; i++ {
		sb.WriteString("    (void)0;\n")
	}
	sb.WriteString("    p->x = 1;\n    return p;\n}\n")
	src := filepath.Join(dir, "big.c")
	if err := os.WriteFile(src, []byte(sb.String()), 0644); err != nil {
		t.Fatal(err)
	}

	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test", RootDir: dir}
	pkgs := []*planner.PlanResult{{
		VulnerabilityType: "null-deref",
		Candidates: []planner.EvidenceItem{{
			SuspicionLevel: "suspected",
			NullOriginTier: "malloc-fail",
			SourceLines:    []int{5},
			Target:         planner.TargetInfo{File: "big.c", Function: "f", Line: 250, Variable: "p"},
		}},
	}}
	if err := o.writeCandidates(pkgs); err != nil {
		t.Fatal(err)
	}
	def := string(mustReadFile(t, filepath.Join(dir, CandidatesDir, "null-deref", "001_big_c_250.md")))
	if !strings.Contains(def, "outside the window") && !strings.Contains(def, "targeted read") {
		t.Errorf("span-truncated candidate must note the window truncation and name the source line to read directly:\n%s", def)
	}
}

// NC-05: one candidate can cover SEVERAL dereference lines of the same
// variable (the variable-level converge). The fix suggestion must tell the
// developer to guard every sink, not just the reported line.
func TestFixSuggestion_NullDerefMultiSink(t *testing.T) {
	s := FixSuggestion("null-deref", "CWE-476", planner.EvidenceItem{
		Target:     planner.TargetInfo{Function: "traverse", Variable: "p", Line: 12},
		DerefLines: []int{12, 13},
	})
	if !strings.Contains(s, "12") || !strings.Contains(s, "13") {
		t.Errorf("multi-sink fix suggestion must name every dereference line (12 and 13), got:\n%s", s)
	}
	if !strings.Contains(s, "every") && !strings.Contains(s, "all") {
		t.Errorf("multi-sink fix suggestion must state the fix covers every sink, got:\n%s", s)
	}
}

// NC-05 sibling: a single-sink candidate keeps the plain suggestion (no
// phantom "other lines" note).
func TestFixSuggestion_NullDerefSingleSink(t *testing.T) {
	s := FixSuggestion("null-deref", "CWE-476", planner.EvidenceItem{
		Target:     planner.TargetInfo{Function: "f", Variable: "p", Line: 12},
		DerefLines: []int{12},
	})
	if strings.Contains(s, "other dereference line") || strings.Contains(s, "every sink") {
		t.Errorf("single-sink fix suggestion must not mention other lines, got:\n%s", s)
	}
}

// NC-02: an assumed-return VARIABLE-path candidate (`p = f(); p->field`, where
// f is a fail-open in-scan callee) carries callee@file:line in its Hint and a
// Verdict Fact promising "its body is embedded under ## Callee Definition".
// The markdown writer must keep that promise for the assumed-return tier too —
// previously only IsCallResultDeref and malloc-fail candidates embedded the
// body, so the AI opened the candidate file, read the promise, and found no
// such section.
func TestWriteCandidates_NullDerefAssumedReturnCalleeDefinition(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "use.c")
	if err := os.WriteFile(src, []byte("int use(void) {\n    T *p = get_obj();\n    return p->x;\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	callee := filepath.Join(dir, "obj.c")
	calleeBody := "/* pad */\nT *get_obj(void) {\n    return g_holder.field;\n}\n"
	if err := os.WriteFile(callee, []byte(calleeBody), 0644); err != nil {
		t.Fatal(err)
	}

	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test", RootDir: dir}
	pkgs := []*planner.PlanResult{{
		VulnerabilityType: "null-deref",
		Candidates: []planner.EvidenceItem{
			{
				SuspicionLevel: "suspected",
				NullOriginTier: "assumed-return",

				CalleeDefFile:      "obj.c",
				CalleeDefLine:      2,
				CalleeDefEndLine:   4,
				CalleeDefSignature: "T *get_obj(void)",
				Target:             planner.TargetInfo{File: "use.c", Function: "use", Line: 3, Variable: "p"},
			},
		},
	}}
	if err := o.writeCandidates(pkgs); err != nil {
		t.Fatal(err)
	}

	def := string(mustReadFile(t, filepath.Join(dir, CandidatesDir, "null-deref", "001_use_c_3.md")))
	if !strings.Contains(def, "## Callee Definition") || !strings.Contains(def, "return g_holder.field;") {
		t.Errorf("assumed-return variable-path candidate must embed the callee body (Hint/VerdictFact/SKILL all promise it):\n%s", def)
	}
}

// A callee whose body cannot be read at report time (file moved/deleted since
// the scan) must degrade to an explicit "body unavailable" note, never a silent
// omission that leaves the classifier thinking the contract is settled.
func TestWriteCandidates_CalleeDefinitionUnreadable(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "call.c")
	if err := os.WriteFile(src, []byte("int handle(void) {\n    pool_new(1);\n    return 0;\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test", RootDir: dir}
	pkgs := []*planner.PlanResult{{
		VulnerabilityType: "unchecked-return",
		Candidates: []planner.EvidenceItem{{
			SuspicionLevel: "suspected",
			Category:       "unchecked_return",
			Contract:       "unknown",
			CalleeDefFile:  "gone.c",
			CalleeDefLine:  7,
			Target:         planner.TargetInfo{File: "call.c", Function: "handle", Line: 2},
		}},
	}}
	if err := o.writeCandidates(pkgs); err != nil {
		t.Fatal(err)
	}
	out := string(mustReadFile(t, filepath.Join(dir, CandidatesDir, "unchecked-return", "001_call_c_2.md")))
	if !strings.Contains(out, "Body unavailable at report time") || !strings.Contains(out, "`gone.c:7`") {
		t.Errorf("unreadable callee body must be explicit, not silent:\n%s", out)
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

// E-06 regression: when a decisive source line (the free site of a UAF, the
// declaration of an uninit read, ...) sits outside the ±8 window, the Code
// Context widens to cover the whole source→sink span so the fragment's
// "free(p) at line N" is checkable in view; a span longer than
// maxContextLines falls back to the plain window.
func TestWriteCandidates_SourceSinkSpanWindow(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "uaf.c")
	var lines []string
	lines = append(lines, "#include <stdlib.h>", "")
	freeLine := len(lines) + 1
	lines = append(lines, "    free(p);")
	for i := 0; i < 27; i++ {
		lines = append(lines, fmt.Sprintf("    pad%d = %d;", i, i))
	}
	useLine := len(lines) + 1
	lines = append(lines, "    x = p->field;")
	lines = append(lines, "}", "")
	for i := 0; i < 250; i++ {
		lines = append(lines, "    more_pad;")
	}
	farUseSink := len(lines) + 1
	lines = append(lines, "    y = p->field;", "}")
	total := len(lines)
	if err := os.WriteFile(src, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test", RootDir: dir}
	mk := func(line, freeLn int) planner.EvidenceItem {
		return planner.EvidenceItem{
			SuspicionLevel: "suspected",
			Category:       "use_after_free",
			SourceLines:    []int{freeLn},
			Target:         planner.TargetInfo{File: "uaf.c", Function: "f", Line: line},
		}
	}
	pkgs := []*planner.PlanResult{{
		VulnerabilityType: "use-after-free",
		Candidates: []planner.EvidenceItem{
			mk(useLine, freeLine),
			mk(farUseSink, freeLine),
		},
	}}
	if err := o.writeCandidates(pkgs); err != nil {
		t.Fatal(err)
	}

	widened := string(mustReadFile(t, filepath.Join(dir, CandidatesDir, "use-after-free", "001_uaf_c_"+strconv.Itoa(useLine)+".md")))
	wantLo, wantHi := freeLine-3, useLine+3
	if wantLo < 1 {
		wantLo = 1
	}
	if !strings.Contains(widened, fmt.Sprintf("`%s:%d-%d`", src, wantLo, wantHi)) {
		t.Errorf("distant free: Code Context should span [%d,%d] (free→use), got:\n%s", wantLo, wantHi, widened)
	}
	if !strings.Contains(widened, fmt.Sprintf("%d |     free(p);", freeLine)) {
		t.Errorf("distant free: widened window must show the free site:\n%s", widened)
	}

	plain := string(mustReadFile(t, filepath.Join(dir, CandidatesDir, "use-after-free", "002_uaf_c_"+strconv.Itoa(farUseSink)+".md")))
	wantLo2, wantHi2 := farUseSink-8, farUseSink+8
	if wantHi2 > total {
		wantHi2 = total
	}
	if !strings.Contains(plain, fmt.Sprintf("`%s:%d-%d`", src, wantLo2, wantHi2)) {
		t.Errorf("overlong span: Code Context should fall back to the ±8 window [%d,%d]:\n%s", wantLo2, wantHi2, plain)
	}

	near := mk(useLine, useLine-2)
	near.SourceLines = []int{useLine - 2}
	pkgs2 := []*planner.PlanResult{{VulnerabilityType: "use-after-free", Candidates: []planner.EvidenceItem{near}}}
	if err := o.writeCandidates(pkgs2); err != nil {
		t.Fatal(err)
	}
	nearMd := string(mustReadFile(t, filepath.Join(dir, CandidatesDir, "use-after-free", "001_uaf_c_"+strconv.Itoa(useLine)+".md")))
	nearLo, nearHi := useLine-8, useLine+8
	if !strings.Contains(nearMd, fmt.Sprintf("`%s:%d-%d`", src, nearLo, nearHi)) {
		t.Errorf("near source: Code Context should stay the ±8 window [%d,%d]:\n%s", nearLo, nearHi, nearMd)
	}
}

// TestWriteCandidates_ExpressionAndContextFallback pins E-07 + E-09:
// a wrapped multi-line statement is rendered in full in the Location section
// (the single-line Source column would show only `memcpy(dst,`), and a
// candidate whose source cannot be read at report time gets an explicit
// degradation note instead of a silently missing Code Context section.
func TestWriteCandidates_ExpressionAndContextFallback(t *testing.T) {
	dir := t.TempDir()
	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test"}
	pkgs := []*planner.PlanResult{{
		VulnerabilityType: "buffer-overflow",
		Candidates: []planner.EvidenceItem{{
			SuspicionLevel: "suspected",
			Target: planner.TargetInfo{
				File: "/repo/gone/wrap.c", Function: "copy", Line: 7, Variable: "dst_buf",
			},
			Expression: "memcpy(dst,\n  src,\n  n)",
			Evidence: []planner.EvidenceFragment{
				{Role: "sink", Detail: "buffer access in function copy at line 7"},
			},
		}},
	}}
	if err := o.writeCandidates(pkgs); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, CandidatesDir, "buffer-overflow", "001_gone_wrap_c_7.md"))
	if err != nil {
		t.Fatalf("candidate evidence file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "**Expression:** `memcpy(dst,   src,   n)`") {
		t.Errorf("Location section should render the full wrapped statement on one line:\n%s", content)
	}
	if !strings.Contains(content, "Source unavailable") {
		t.Errorf("an unreadable source must render an explicit degradation note, not a silent gap:\n%s", content)
	}
	if strings.Contains(content, "is the reported location") {
		t.Errorf("no context window should be rendered when the source is unavailable:\n%s", content)
	}
}

// TestWriteCandidates_VariableExpressionFallbackCollapse pins the
// unchecked-return shape: the Variable column IS the expression fallback (no
// variable key in the event props), so it carries the detector's raw multi-line
// text. The Location section must collapse it to one line instead of rendering
// wrapped C, and must not duplicate it as a separate Expression row.
func TestWriteCandidates_VariableExpressionFallbackCollapse(t *testing.T) {
	dir := t.TempDir()
	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test"}
	expr := "obj_pool_new(\n            n)"
	pkgs := []*planner.PlanResult{{
		VulnerabilityType: "unchecked-return",
		Candidates: []planner.EvidenceItem{{
			SuspicionLevel: "suspected",
			Target: planner.TargetInfo{
				File: "/repo/wrap.c", Function: "caller", Line: 5, Variable: expr,
			},
			Expression: expr,
			Evidence: []planner.EvidenceFragment{
				{Role: "sink", Detail: "return value of obj_pool_new is not checked in function caller at line 5"},
			},
		}},
	}}
	if err := o.writeCandidates(pkgs); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, CandidatesDir, "unchecked-return", "001_repo_wrap_c_5.md"))
	if err != nil {
		t.Fatalf("candidate evidence file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "**Variable:** `obj_pool_new(             n)`") {
		t.Errorf("Variable fallback should be collapsed to one line:\n%s", content)
	}
	if strings.Contains(content, "**Expression:**") {
		t.Errorf("Variable==Expression must not render a duplicate Expression row:\n%s", content)
	}
	if strings.Contains(content, "\n            n)") {
		t.Errorf("no raw multi-line text should survive in the Location section:\n%s", content)
	}
}

// TestSourceWindowText pins the re-review window: the ±ctx block must expose
// the statements around a machine finding (the guard/return that settles it)
// and mark the finding line, while a disabled window (ctx<=0) yields "".
func TestSourceWindowText(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "w.c")
	lines := "int f(void) {\n    char *p = malloc(4);\n    if (p) {\n        p[0] = 0;\n        free(p);\n    }\n    return 0;\n}\n"
	if err := os.WriteFile(src, []byte(lines), 0644); err != nil {
		t.Fatal(err)
	}

	got := SourceWindowText(src, 4, 2, dir)
	for _, want := range []string{"  2 |     char *p = malloc(4);", "> 4 |         p[0] = 0;", "  6 |     }"} {
		if !strings.Contains(got, want) {
			t.Errorf("window missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "  1 |") || strings.Contains(got, "  7 |") {
		t.Errorf("window of ±2 must not include lines outside [2,6]:\n%s", got)
	}
	if disable := SourceWindowText(src, 4, 0, dir); disable != "" {
		t.Errorf("ctx<=0 must disable the window, got: %q", disable)
	}
	if missing := SourceWindowText(filepath.Join(dir, "nope.c"), 4, 2, dir); missing != "" {
		t.Errorf("unreadable file must degrade to the empty string, got: %q", missing)
	}
}
