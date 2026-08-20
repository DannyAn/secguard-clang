package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
	"github.com/DannyAn/secguard-clang/internal/report"
)

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
	for _, a := range args {
		if a == "--"+flag {
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

func runReportCmd(ctx context.Context, args []string) int {
	dbPath, dbExplicit, remaining := parseDBFlag(args)

	dbPath = resolveDBPath(dbExplicit, dbPath, ".")

	store, err := openStore(ctx, dbPath)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to open database: %v", err))
		return 1
	}
	defer store.Close()

	if hasFlag(remaining, "write") {
		confidence := parseFloatFlag(remaining, "confidence")
		if confidence > 1.0 {
			confidence = confidence / 100.0
		}

		finding := &db.Finding{
			RuleID:         parseStringFlag(remaining, "rule-id"),
			Severity:       parseStringFlag(remaining, "severity"),
			Confidence:     confidence,
			Evidence:       parseStringFlag(remaining, "evidence"),
			Status:         parseStringFlag(remaining, "status"),
			FilePath:       parseStringFlag(remaining, "file"),
			LineNumber:     parseIntFlag(remaining, "line"),
			FunctionName:   parseStringFlag(remaining, "function"),
			Properties:     parseStringFlag(remaining, "properties"),
			Summary:        parseStringFlag(remaining, "summary"),
			Reasoning:      parseStringFlag(remaining, "reasoning"),
			FixStrategy:    parseStringFlag(remaining, "fix-strategy"),
			ExceptionCheck: parseStringFlag(remaining, "exception-check"),
			ScanID:         parseStringFlag(remaining, "scan-id"),
		}

		if finding.Severity == "" {
			finding.Severity = "info"
		} else {
			finding.Severity = strings.ToLower(finding.Severity)
		}
		finding.Status = strings.ToLower(finding.Status)

		cweNorm := strings.ToUpper(strings.TrimSpace(finding.RuleID))
		if cweNorm != "" && !db.SupportedFindingCWEs[cweNorm] {
			WriteErrorJSON(fmt.Sprintf("unsupported rule_id %q: SecGuard pipeline does not detect this vulnerability type. Supported CWEs: %s. Agent-observed findings for unsupported types should be reported as observations, not persisted.", finding.RuleID, db.SupportedCWEsList()))
			return 1
		}

		// Validate scan_id exists so findings can never be silently attached to
		// a nonexistent scan (e.g. a stale or typo'd id from the agent). An
		// empty scan_id is allowed for backward compatibility with callers that
		// don't track scans.
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

		id, err := store.InsertFinding(ctx, finding)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to write finding: %v", err))
			return 1
		}

		perFindingPath := rewritePerFindingAfterWrite(remaining, finding)

		WriteJSON(map[string]interface{}{
			"id":               id,
			"status":           "ok",
			"per_finding_path": perFindingPath,
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
		if reviewStatus == "" {
			WriteErrorJSON("--review requires --review-status (confirmed|dismissed|suspected-kept)")
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
		if reviewStatus == "suspected-kept" {
			finalStatus = "suspected"
		}
		perFindingPath := ""
		scanDir := resolveScanDir(remaining, f.ScanID)
		if scanDir != "" && f.FilePath != "" && f.LineNumber > 0 {
			vulnType := planner.TypeForCWE(f.RuleID)
			if vulnType != "" {
				perFindingPath, _ = report.RewritePerFinding(scanDir, vulnType, f.FilePath, f.LineNumber, report.PerFindingUpdate{
					Status:       finalStatus,
					Severity:     f.Severity,
					Confidence:   f.Confidence,
					FunctionName: f.FunctionName,
				})
			}
		}

		WriteJSON(map[string]interface{}{
			"id":               findingID,
			"review_status":    reviewStatus,
			"status":           "ok",
			"per_finding_path": perFindingPath,
		})
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

		stats, err := store.ListScanStats(ctx, scanID)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to list scan stats: %v", err))
			return 1
		}

		scanFindings, _ := store.ListFindingsByScanID(ctx, scanID)
		type vulnCounts struct {
			confirmed, suspected, dismissed int
		}
		countsByVuln := make(map[string]*vulnCounts)
		for _, f := range scanFindings {
			vt := planner.TypeForCWE(f.RuleID)
			if vt == "" {
				continue
			}
			if countsByVuln[vt] == nil {
				countsByVuln[vt] = &vulnCounts{}
			}
			switch f.Status {
			case "confirmed":
				countsByVuln[vt].confirmed++
			case "suspected":
				countsByVuln[vt].suspected++
			case "dismissed":
				countsByVuln[vt].dismissed++
			}
		}

		audits := make([]vulnAuditEntry, 0, len(stats))
		for _, st := range stats {
			vc := countsByVuln[st.VulnType]
			if vc == nil {
				vc = &vulnCounts{}
			}
			audits = append(audits, vulnAuditEntry{
				VulnType:   st.VulnType,
				SeedCount:  st.SeedCount,
				FinalCount: st.FinalCount,
				Filters:    st.FilterChain,
				Confirmed:  vc.confirmed,
				Suspected:  vc.suspected,
				Dismissed:  vc.dismissed,
			})
		}

		outputDir := parseStringFlag(remaining, "output-dir")
		if outputDir != "" {
			auditPath := filepath.Join(outputDir, "audit-report.md")
			if err := writeAuditReport(auditPath, scanID, audits); err != nil {
				WriteErrorJSON(fmt.Sprintf("failed to write audit report: %v", err))
				return 1
			}
			WriteJSON(map[string]interface{}{
				"scan_id":    scanID,
				"audit_path": auditPath,
				"vuln_count": len(audits),
				"status":     "ok",
			})
		} else {
			WriteJSON(map[string]interface{}{
				"scan_id": scanID,
				"audits":  audits,
			})
		}
		return 0
	}

	statusFilter := parseStringFlag(remaining, "status")

	var findings []*db.Finding
	if statusFilter != "" {
		findings, err = store.ListFindingsByStatus(ctx, statusFilter)
	} else {
		findings, err = store.ListFindings(ctx)
	}
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to list findings: %v", err))
		return 1
	}

	if len(findings) == 0 {
		WriteJSON(map[string]interface{}{
			"findings": []interface{}{},
			"count":    0,
			"message":  "no findings in database; run 'secguard report --write ...' to persist findings after classifying candidates",
		})
		return 0
	}
	WriteJSON(findings)
	return 0
}

type vulnAuditEntry struct {
	VulnType   string `json:"vuln_type"`
	SeedCount  int    `json:"seed_count"`
	FinalCount int    `json:"final_count"`
	Filters    string `json:"filter_chain"`
	Confirmed  int    `json:"confirmed"`
	Suspected  int    `json:"suspected"`
	Dismissed  int    `json:"dismissed"`
}

func writeAuditReport(auditPath, scanID string, audits []vulnAuditEntry) error {
	if err := os.MkdirAll(filepath.Dir(auditPath), 0755); err != nil {
		return err
	}

	var b strings.Builder
	b.WriteString("# SecGuard Audit Report\n\n")
	b.WriteString(fmt.Sprintf("**Scan ID:** `%s`\n\n", scanID))
	b.WriteString("## Per-Skill Pipeline Statistics\n\n")
	b.WriteString("| Vulnerability Type | Seed | Final | AI Confirmed | AI Suspected | AI Dismissed | Filter Efficiency | AI Accuracy |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")

	totalSeed, totalFinal, totalConfirmed, totalSuspected, totalDismissed := 0, 0, 0, 0, 0
	for _, a := range audits {
		filterEff := "n/a"
		if a.SeedCount > 0 {
			filterEff = fmt.Sprintf("%.0f%%", float64(a.SeedCount-a.FinalCount)/float64(a.SeedCount)*100)
		}
		aiAcc := "n/a"
		classified := a.Confirmed + a.Dismissed
		if classified > 0 {
			aiAcc = fmt.Sprintf("%.0f%%", float64(a.Confirmed)/float64(classified)*100)
		}
		b.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d | %d | %s | %s |\n",
			a.VulnType, a.SeedCount, a.FinalCount, a.Confirmed, a.Suspected, a.Dismissed, filterEff, aiAcc))
		totalSeed += a.SeedCount
		totalFinal += a.FinalCount
		totalConfirmed += a.Confirmed
		totalSuspected += a.Suspected
		totalDismissed += a.Dismissed
	}

	b.WriteString(fmt.Sprintf("| **TOTAL** | **%d** | **%d** | **%d** | **%d** | **%d** |", totalSeed, totalFinal, totalConfirmed, totalSuspected, totalDismissed))
	if totalSeed > 0 {
		b.WriteString(fmt.Sprintf(" **%.0f%%** |", float64(totalSeed-totalFinal)/float64(totalSeed)*100))
	} else {
		b.WriteString(" n/a |")
	}
	totalClassified := totalConfirmed + totalDismissed
	if totalClassified > 0 {
		b.WriteString(fmt.Sprintf(" **%.0f%%** |\n\n", float64(totalConfirmed)/float64(totalClassified)*100))
	} else {
		b.WriteString(" n/a |\n\n")
	}

	// AI Value Summary: make the human impact of the AI classification layer
	// explicit and auditable. Every converged candidate should receive a
	// classification; a nonzero "without AI classification" count is a process
	// gap (e.g. a candidate whose skill was not loaded), not a design feature.
	classifiedByAI := totalConfirmed + totalSuspected + totalDismissed
	unclassified := totalFinal - classifiedByAI
	if unclassified < 0 {
		unclassified = 0
	}
	b.WriteString("## AI Value Summary\n\n")
	b.WriteString("| Metric | Value |\n")
	b.WriteString("|--------|-------|\n")
	fmt.Fprintf(&b, "| Raw evidence seeds | %d |\n", totalSeed)
	fmt.Fprintf(&b, "| Converged candidates (after pipeline filters) | %d |\n", totalFinal)
	fmt.Fprintf(&b, "| Candidates classified by AI | %d |\n", classifiedByAI)
	fmt.Fprintf(&b, "| Candidates without AI classification | %d |\n", unclassified)
	fmt.Fprintf(&b, "| AI confirmed (actionable, with fix suggestion) | %d |\n", totalConfirmed)
	fmt.Fprintf(&b, "| AI suspected (needs human decision) | %d |\n", totalSuspected)
	fmt.Fprintf(&b, "| AI dismissed (false positives, evidence recorded) | %d |\n", totalDismissed)
	fmt.Fprintf(&b, "| Actionable findings for human review | %d |\n", totalConfirmed+totalSuspected)
	if totalSeed > 0 {
		fmt.Fprintf(&b, "| Pipeline filter efficiency | %.0f%% |\n", float64(totalSeed-totalFinal)/float64(totalSeed)*100)
	} else {
		b.WriteString("| Pipeline filter efficiency | n/a |\n")
	}
	if totalClassified > 0 {
		fmt.Fprintf(&b, "| AI accuracy (confirmed / confirmed+dismissed) | %.0f%% |\n\n", float64(totalConfirmed)/float64(totalClassified)*100)
	} else {
		b.WriteString("| AI accuracy (confirmed / confirmed+dismissed) | n/a |\n\n")
	}

	b.WriteString("## Filter Chain Details\n\n")
	for _, a := range audits {
		b.WriteString(fmt.Sprintf("### %s\n\n", a.VulnType))
		b.WriteString(fmt.Sprintf("- **Seed count:** %d\n", a.SeedCount))
		b.WriteString(fmt.Sprintf("- **Final count:** %d\n", a.FinalCount))
		if a.Filters != "" {
			b.WriteString(fmt.Sprintf("- **Filter chain:** `%s`\n", a.Filters))
		}
		b.WriteString(fmt.Sprintf("- **AI classification:** confirmed=%d, suspected=%d, dismissed=%d\n\n", a.Confirmed, a.Suspected, a.Dismissed))
	}

	return os.WriteFile(auditPath, []byte(b.String()), 0644)
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

func rewritePerFindingAfterWrite(args []string, finding *db.Finding) string {
	scanDir := resolveScanDir(args, finding.ScanID)
	if scanDir == "" || finding.FilePath == "" || finding.LineNumber <= 0 {
		return ""
	}
	vulnType := planner.TypeForCWE(finding.RuleID)
	if vulnType == "" {
		return ""
	}
	newPath, _ := report.RewritePerFinding(scanDir, vulnType, finding.FilePath, finding.LineNumber, report.PerFindingUpdate{
		Summary:        finding.Summary,
		Reasoning:      finding.Reasoning,
		FixStrategy:    finding.FixStrategy,
		ExceptionCheck: finding.ExceptionCheck,
		Status:         finding.Status,
		Severity:       finding.Severity,
		Confidence:     finding.Confidence,
		FunctionName:   finding.FunctionName,
	})
	return newPath
}
