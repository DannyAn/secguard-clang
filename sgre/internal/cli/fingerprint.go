package cli

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
)

// computeFingerprint returns the content-addressed, scan-independent identity of
// a finding. It hashes rule_id + file + function + the trimmed source statement
// at file:line, so a finding survives line-number drift (the same statement
// moved by unrelated insertions keeps the same fingerprint) but changes when the
// sink statement itself is edited. This is the incremental-review dedup key.
func computeFingerprint(ruleID, filePath, functionName string, line int) string {
	payload := strings.ToUpper(strings.TrimSpace(ruleID)) + "\x00" +
		filePath + "\x00" +
		functionName + "\x00" +
		readStatement(filePath, line)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// readStatement reads the trimmed text of a single source line, or "" when the
// file/line is unavailable. A missing source degrades the fingerprint to
// (rule, file, function) — still stable, but less precise.
func readStatement(filePath string, line int) string {
	if filePath == "" || line <= 0 {
		return ""
	}
	f, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		n++
		if n == line {
			return strings.TrimSpace(sc.Text())
		}
		if n > line {
			break
		}
	}
	return ""
}
