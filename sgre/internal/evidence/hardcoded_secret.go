package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type HardcodedSecretDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewHardcodedSecretDetector(store db.Store, p *parser.Parser, logger *log.Logger) *HardcodedSecretDetector {
	return &HardcodedSecretDetector{store: store, parser: p, logger: logger}
}

func (d *HardcodedSecretDetector) Name() string { return "hardcoded_secret" }

func (d *HardcodedSecretDetector) Domain() string { return "trust" }

func (d *HardcodedSecretDetector) Capabilities() []string {
	return []string{"hardcoded-password", "hardcoded-api-key", "hardcoded-token", "hardcoded-private-key"}
}

var secretVarPattern = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|api_key|apikey|access_key|private_key|token|credential|auth_key)`)

var highEntropyHints = []string{
	"sk-", "eyJ", "-----BEGIN", "AKIA", "ghp_", "gho_", "xoxb-", "xoxp-",
}

func (d *HardcodedSecretDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return result, fmt.Errorf("hardcoded_secret: list functions: %w", err)
	}

	processedFiles := make(map[int64]bool)
	for _, f := range funcs {
		file, _ := d.store.GetFileByID(ctx, f.FileID)
		if file == nil {
			continue
		}
		if processedFiles[file.ID] {
			continue
		}
		processedFiles[file.ID] = true

		source, err := os.ReadFile(file.Path)
		if err != nil {
			continue
		}
		tree, err := d.parser.ParseCached(source, file.Path)
		if err != nil {
			continue
		}
		root := tree.RootNode()

		for _, init := range root.FindAll("init_declarator") {
			varName := ""
			for _, id := range init.FindAll("identifier") {
				varName = id.Text()
				break
			}
			if varName == "" {
				continue
			}

			value := extractInitializerValue(init)
			if value == "" {
				continue
			}

			isSecretVar := secretVarPattern.MatchString(varName)
			isHighEntropy := false
			for _, hint := range highEntropyHints {
				if strings.HasPrefix(value, hint) {
					isHighEntropy = true
					break
				}
			}
			isLongLiteral := len(value) >= 16 && !isNumericLiteral(value)

			if !isSecretVar && !isHighEntropy && !isLongLiteral {
				continue
			}
			if isLongLiteral && !isSecretVar && !isHighEntropy {
				continue
			}

			locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: init.StartLine(), Column: init.StartColumn()})
			props, _ := json.Marshal(map[string]string{
				"variable": varName,
				"value":    value,
				"category": "hardcoded_secret",
			})
			_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
				EventType:  "HARDCODED_SECRET",
				EntityID:   f.ID,
				LocationID: locID,
				Properties: string(props),
			})
			if err == nil {
				result.EventsCreated++
			}
		}

		d.detectRegSetValueEx(ctx, root, file, &result)

		tree.Close()
	}

	return result, nil
}

func (d *HardcodedSecretDetector) detectRegSetValueEx(ctx context.Context, root parser.Node, file *db.File, result *DetectResult) {
	for _, call := range root.FindAll("call_expression") {
		callName := extractCallName(call)
		if callName != "RegSetValueExA" && callName != "RegSetValueExW" && callName != "RegSetValueEx" {
			continue
		}
		args := extractCallArgs(call)
		if len(args) < 5 {
			continue
		}
		valueName := strings.Trim(args[1], "\"")
		if !secretVarPattern.MatchString(valueName) {
			continue
		}
		// The value argument is often a cast-prefixed literal, e.g.
		// (BYTE*)"P@ssw0rd!" or (const BYTE*)"secret". Extract the string
		// literal rather than requiring the arg to start with a quote.
		valueData := extractStringLiteral(args[4])
		if valueData == "" {
			continue
		}

		funcs, _ := d.store.ListFunctions(ctx)
		var funcID int64
		for _, f := range funcs {
			if f.FileID == file.ID && call.StartLine() >= f.StartLine && call.StartLine() <= f.EndLine {
				funcID = f.ID
				break
			}
		}

		locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()})
		props, _ := json.Marshal(map[string]string{
			"api":      callName,
			"name":     valueName,
			"value":    valueData,
			"category": "hardcoded_secret",
		})
		_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
			EventType:  "HARDCODED_SECRET",
			EntityID:   funcID,
			LocationID: locID,
			Properties: string(props),
		})
		if err == nil {
			result.EventsCreated++
		}
	}
}

func extractInitializerValue(init parser.Node) string {
	for _, child := range init.NamedChildren() {
		if child.Kind() == "string_literal" {
			text := child.Text()
			text = strings.Trim(text, "\"")
			text = strings.Trim(text, "'")
			return text
		}
	}
	return ""
}

// extractStringLiteral returns the contents of the first double-quoted string
// in text, ignoring any cast prefix such as (BYTE*) or (const BYTE*). It
// returns "" when text contains no string literal.
func extractStringLiteral(text string) string {
	start := strings.IndexByte(text, '"')
	if start < 0 {
		return ""
	}
	end := strings.IndexByte(text[start+1:], '"')
	if end < 0 {
		return ""
	}
	return text[start+1 : start+1+end]
}

func isNumericLiteral(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			if c != '.' && c != '-' && c != '+' && c != 'x' && c != 'X' && c != 'a' && c != 'b' && c != 'c' && c != 'd' && c != 'e' && c != 'f' && c != 'A' && c != 'B' && c != 'C' && c != 'D' && c != 'E' && c != 'F' {
				return false
			}
		}
	}
	return true
}
