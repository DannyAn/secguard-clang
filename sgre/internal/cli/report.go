package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
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

func runReportCmd(ctx context.Context, args []string) int {
	dbPath, remaining := parseDBFlag(args)

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
			RuleID:       parseStringFlag(remaining, "rule-id"),
			Severity:     parseStringFlag(remaining, "severity"),
			Confidence:   confidence,
			Evidence:     parseStringFlag(remaining, "evidence"),
			Status:       parseStringFlag(remaining, "status"),
			FilePath:     parseStringFlag(remaining, "file"),
			LineNumber:   parseIntFlag(remaining, "line"),
			FunctionName: parseStringFlag(remaining, "function"),
			Properties:   parseStringFlag(remaining, "properties"),
			ScanID:       parseStringFlag(remaining, "scan-id"),
		}

		if finding.Severity == "" {
			finding.Severity = "info"
		} else {
			finding.Severity = strings.ToLower(finding.Severity)
		}
		finding.Status = strings.ToLower(finding.Status)

		cweNorm := strings.ToUpper(strings.TrimSpace(finding.RuleID))
		if cweNorm != "" && !db.SupportedFindingCWEs[cweNorm] {
			WriteErrorJSON(fmt.Sprintf("unsupported rule_id %q: SecGuard pipeline does not detect this vulnerability type. Supported CWEs: CWE-476, CWE-787, CWE-401, CWE-78, CWE-89, CWE-404, CWE-457, CWE-416, CWE-415, CWE-134, CWE-190, CWE-362, CWE-798, CWE-667, CWE-327. Agent-observed findings for unsupported types should be reported as observations, not persisted.", finding.RuleID))
			return 1
		}

		id, err := store.InsertFinding(ctx, finding)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to write finding: %v", err))
			return 1
		}

		WriteJSON(map[string]interface{}{
			"id":     id,
			"status": "ok",
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

		cweToVulnType := map[string]string{
			"CWE-476": "null-deref", "CWE-787": "buffer-overflow", "CWE-401": "memory-leak",
			"CWE-78": "injection", "CWE-89": "injection", "CWE-404": "resource-leak",
			"CWE-457": "uninit", "CWE-416": "use-after-free",
			"CWE-415": "double-free", "CWE-134": "format-string",
			"CWE-190": "integer-overflow", "CWE-362": "race-condition",
			"CWE-798": "hardcoded-secret", "CWE-667": "deadlock",
			"CWE-327": "crypto-misuse",
		}

		scanFindings, _ := store.ListFindingsByScanID(ctx, scanID)
		type vulnCounts struct {
			confirmed, suspected, dismissed int
		}
		countsByVuln := make(map[string]*vulnCounts)
		for _, f := range scanFindings {
			vt := cweToVulnType[strings.ToUpper(f.RuleID)]
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

	if findings == nil {
		findings = []*db.Finding{}
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
