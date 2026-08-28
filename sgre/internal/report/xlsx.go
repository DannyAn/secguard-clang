package report

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
	"github.com/xuri/excelize/v2"
)

// xlsxHeaders is the single source of truth for the result.xlsx column order;
// the writer and the test both read it so a reorder is caught in CI.
var xlsxHeaders = []string{
	"序号", "漏洞类型", "CWE", "严重级别", "结论", "置信度",
	"文件", "行号", "函数", "问题摘要", "详细分析", "修复建议", "代码上下文",
}

// xlsxColumnWidths maps each column letter to its width (in Excel character
// units). Long text columns get room to wrap; the source-context column is the
// widest so a gutter-numbered C block stays readable.
var xlsxColumnWidths = map[string]float64{
	"A": 6, "B": 16, "C": 12, "D": 10, "E": 10, "F": 8,
	"G": 40, "H": 8, "I": 24, "J": 40, "K": 50, "L": 50, "M": 70,
}

// WriteXlsxFromFindings regenerates result.xlsx from the AI's persisted
// findings. It carries the same filter contract as WriteReportFromFindings and
// WriteSarifFromFindings — only confirmed + suspected are included, dismissed
// false-positives are excluded — but renders every finding as one spreadsheet
// row with a source-context snippet, so a developer can locate, analyze, and
// confirm a finding without opening the source tree.
func WriteXlsxFromFindings(xlsxPath, rootDir string, findings []*db.Finding) error {
	// The xlsx lives inside the scan directory, so the project root (and with it
	// the source tree) is derivable without extra plumbing, matching SARIF.
	sourceRoot := rootDir
	if sourceRoot == "" {
		sourceRoot = projectRootFromScanDir(filepath.Dir(xlsxPath))
	}

	// Filter to actionable findings and normalize each into a stable sort key.
	type row struct {
		vulnType string
		cwe      string
		file     string
		line     int
		id       int64
		f        *db.Finding
	}
	rows := make([]row, 0, len(findings))
	for _, f := range findings {
		status := f.FinalStatus()
		if status != "confirmed" && status != "suspected" {
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
		rows = append(rows, row{
			vulnType: vulnType,
			cwe:      cwe,
			file:     f.FilePath,
			line:     f.LineNumber,
			id:       f.ID,
			f:        f,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].vulnType != rows[j].vulnType {
			return rows[i].vulnType < rows[j].vulnType
		}
		if rows[i].file != rows[j].file {
			return rows[i].file < rows[j].file
		}
		if rows[i].line != rows[j].line {
			return rows[i].line < rows[j].line
		}
		return rows[i].id < rows[j].id
	})

	f := excelize.NewFile()
	defer f.Close()

	const sheet = "Findings"
	if err := f.SetSheetName("Sheet1", sheet); err != nil {
		return err
	}

	headerStyle, err := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "FFFFFF", Family: "Microsoft YaHei"},
		Fill:      excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"4472C4"}},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center", WrapText: true},
	})
	if err != nil {
		return err
	}
	bodyStyle, err := f.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{Vertical: "top", WrapText: true},
	})
	if err != nil {
		return err
	}
	codeStyle, err := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Family: "Consolas"},
		Alignment: &excelize.Alignment{Vertical: "top", WrapText: true},
	})
	if err != nil {
		return err
	}

	// Header row.
	for i, h := range xlsxHeaders {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		if err := f.SetCellValue(sheet, cell, h); err != nil {
			return err
		}
	}
	if err := f.SetRowStyle(sheet, 1, 1, headerStyle); err != nil {
		return err
	}
	if err := f.SetRowHeight(sheet, 1, 22); err != nil {
		return err
	}

	// Data rows (r = 2..N+1).
	for i, r := range rows {
		finding := r.f
		rIdx := i + 2 // Excel row number (header occupies row 1)

		severity := finding.Severity
		if severity == "" {
			severity = "info"
		}
		summary := finding.Summary
		if summary == "" {
			summary = finding.Reasoning
		}
		if summary == "" {
			summary = finding.Evidence
		}
		if summary == "" {
			summary = finding.FunctionName
		}
		summary = strings.ReplaceAll(summary, "\n", " ")

		reasoning := finding.Reasoning
		if finding.ExceptionCheck != "" {
			if reasoning != "" {
				reasoning += "\n\n"
			}
			reasoning += "[exception check] " + finding.ExceptionCheck
		}

		ctx := readCodeContext(finding.FilePath, finding.LineNumber, ContextLines, sourceRoot)
		snippet := numberedContext(ctx)

		// Column A is the 1-based sequence number.
		cells := map[string]interface{}{
			"A": i + 1,
			"B": r.vulnType,
			"C": r.cwe,
			"D": severity,
			"E": finding.FinalStatus(),
			"G": displayPath(finding.FilePath, sourceRoot),
			"I": finding.FunctionName,
			"J": summary,
			"K": reasoning,
			"L": finding.FixStrategy,
			"M": snippet,
		}
		if finding.Confidence > 0 {
			cells["F"] = finding.Confidence
		} else {
			cells["F"] = ""
		}
		if finding.LineNumber > 0 {
			cells["H"] = finding.LineNumber
		} else {
			cells["H"] = ""
		}

		for col, val := range cells {
			cell, _ := excelize.CoordinatesToCellName(columnIndex(col), rIdx)
			if err := f.SetCellValue(sheet, cell, val); err != nil {
				return err
			}
		}
	}

	lastRow := len(rows) + 1
	if lastRow >= 2 {
		if err := f.SetRowStyle(sheet, 2, lastRow, bodyStyle); err != nil {
			return err
		}
		if err := f.SetColStyle(sheet, "M", codeStyle); err != nil {
			return err
		}
	}

	for col, width := range xlsxColumnWidths {
		if err := f.SetColWidth(sheet, col, col, width); err != nil {
			return err
		}
	}

	if err := f.SetPanes(sheet, &excelize.Panes{
		Freeze:      true,
		Split:       false,
		XSplit:      0,
		YSplit:      1,
		TopLeftCell: "A2",
		ActivePane:  "bottomLeft",
	}); err != nil {
		return err
	}

	if err := f.AutoFilter(sheet, fmt.Sprintf("A1:M%d", lastRow), nil); err != nil {
		return err
	}

	return f.SaveAs(xlsxPath)
}

// columnIndex maps a column letter ("A".."M") to its 1-based index. It is the
// inverse of excelize.CoordinatesToCellName for the single-letter range used
// here, so the writer can address cells by letter regardless of row.
func columnIndex(col string) int {
	return int(col[0]-'A') + 1
}

// displayPath trims the project root from a file path so the spreadsheet (and
// the markdown/SARIF tables) show a repo-relative path. When the root cannot be
// derived — or the path is not under it — the input is returned unchanged
// (absolute stays absolute, a stray relative stays relative), so a consumer can
// always re-locate the file rather than chase a truncated tail.
func displayPath(p, root string) string {
	if root != "" && (p == root || strings.HasPrefix(p, root+string(filepath.Separator))) {
		p = strings.TrimPrefix(p, root)
		p = strings.TrimPrefix(p, string(filepath.Separator))
	}
	return p
}

// numberedContext renders a source region as gutter-numbered plain text with
// the finding line marked `>`, for an Excel cell. Unlike codeContext.render()
// (which wraps the block in ```c fences for Markdown) this is fence-free so it
// reads cleanly inside a spreadsheet cell.
func numberedContext(ctx *codeContext) string {
	if ctx == nil || len(ctx.Lines) == 0 {
		return ""
	}
	width := len(strconv.Itoa(ctx.EndLine))
	var b strings.Builder
	for i, text := range ctx.Lines {
		n := ctx.StartLine + i
		marker := " "
		if n == ctx.Line {
			marker = ">"
		}
		if i > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "%s %*d | %s", marker, width, n, text)
	}
	return b.String()
}
