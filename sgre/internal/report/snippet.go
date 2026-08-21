package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ContextLines is how many source lines are rendered on each side of a
// finding's line in the verdict markdown and in the SARIF context region.
// A report that forces the reader to open an editor to judge a finding is an
// incomplete report, so the source region travels with the verdict.
//
// It is a var so cli can expose it as `--context-lines`; 0 disables source
// embedding entirely (for repositories where source must not be copied into
// report artifacts).
var ContextLines = 15

// maxContextLines caps the window so one finding cannot turn into a file dump.
const maxContextLines = 200

// maxSnippetLineLen truncates pathological lines (minified or generated code)
// so a single line cannot blow up the report.
const maxSnippetLineLen = 400

// codeContext is a resolved source region around a finding.
type codeContext struct {
	Path      string
	StartLine int
	EndLine   int
	Line      int
	Lines     []string // the region, in order, starting at StartLine
}

// resolveSourcePath finds the source file on disk. A finding's file path may be
// absolute (from the pipeline), repo-relative (as the agent copied it out of
// report.md), or relative to the project root, so every plausible base is tried
// before giving up.
func resolveSourcePath(filePath string, roots ...string) string {
	if filePath == "" {
		return ""
	}
	if filepath.IsAbs(filePath) {
		if isRegularFile(filePath) {
			return filePath
		}
	}
	candidates := []string{}
	if !filepath.IsAbs(filePath) {
		candidates = append(candidates, filePath)
	}
	for _, root := range roots {
		if root == "" {
			continue
		}
		candidates = append(candidates, filepath.Join(root, filePath))
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, filePath))
	}
	for _, c := range candidates {
		if isRegularFile(c) {
			return c
		}
	}
	return ""
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// readCodeContext reads the ±ctx line window around line. It returns nil when
// source embedding is disabled, the file cannot be located/read, or the line is
// outside the file — a missing snippet degrades the report, it never fails it.
func readCodeContext(filePath string, line, ctx int, roots ...string) *codeContext {
	if ctx <= 0 || line <= 0 {
		return nil
	}
	if ctx > maxContextLines {
		ctx = maxContextLines
	}
	path := resolveSourcePath(filePath, roots...)
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	all := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	// Drop the trailing empty element a final newline produces.
	if n := len(all); n > 0 && all[n-1] == "" {
		all = all[:n-1]
	}
	if line > len(all) {
		return nil
	}
	start := line - ctx
	if start < 1 {
		start = 1
	}
	end := line + ctx
	if end > len(all) {
		end = len(all)
	}
	region := make([]string, 0, end-start+1)
	for _, l := range all[start-1 : end] {
		if len(l) > maxSnippetLineLen {
			l = l[:maxSnippetLineLen] + " …"
		}
		region = append(region, l)
	}
	return &codeContext{Path: path, StartLine: start, EndLine: end, Line: line, Lines: region}
}

// render produces a gutter-numbered C block with the finding line marked, in
// the compiler-diagnostic style developers already read fluently.
func (c *codeContext) render() string {
	if c == nil || len(c.Lines) == 0 {
		return ""
	}
	width := len(strconv.Itoa(c.EndLine))
	var b strings.Builder
	b.WriteString("```c\n")
	for i, text := range c.Lines {
		n := c.StartLine + i
		marker := " "
		if n == c.Line {
			marker = ">"
		}
		fmt.Fprintf(&b, "%s %*d | %s\n", marker, width, n, text)
	}
	b.WriteString("```\n")
	return b.String()
}

// text returns the region without gutters, for SARIF snippets.
func (c *codeContext) text() string {
	if c == nil {
		return ""
	}
	return strings.Join(c.Lines, "\n")
}

// lineText returns just the finding line, for the SARIF region snippet.
func (c *codeContext) lineText() string {
	if c == nil {
		return ""
	}
	idx := c.Line - c.StartLine
	if idx < 0 || idx >= len(c.Lines) {
		return ""
	}
	return strings.TrimSpace(c.Lines[idx])
}

// projectRootFromScanDir maps <root>/.codeagent/<product>/scans/<scan-id> back
// to <root>, so source files can be resolved from a scan directory alone
// without threading the project root through every call site.
func projectRootFromScanDir(scanDir string) string {
	if scanDir == "" {
		return ""
	}
	// scans/<scan-id> → scans → <product> → .codeagent → <root>
	root := scanDir
	for i := 0; i < 4; i++ {
		root = filepath.Dir(root)
	}
	if root == "." || root == string(filepath.Separator) {
		return ""
	}
	return root
}
