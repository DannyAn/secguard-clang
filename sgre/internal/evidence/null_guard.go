package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type NullGuardDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewNullGuardDetector(store db.Store, p *parser.Parser, logger *log.Logger) *NullGuardDetector {
	return &NullGuardDetector{store: store, parser: p, logger: logger}
}

func (d *NullGuardDetector) Name() string { return "null_guard" }

func (d *NullGuardDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return result, fmt.Errorf("null guard: list functions: %w", err)
	}

	for _, f := range funcs {
		file, _ := d.store.GetFileByID(ctx, f.FileID)
		if file == nil {
			continue
		}
		source, err := os.ReadFile(file.Path)
		if err != nil {
			continue
		}
		tree, err := d.parser.ParseCached(source, file.Path)
		if err != nil {
			continue
		}
		root := tree.RootNode()

		d.detectGuards(ctx, f, file, root, &result)
		d.detectEarlyReturnGuards(ctx, f, file, root, &result)

		tree.Close()
	}

	return result, nil
}

func (d *NullGuardDetector) detectGuards(ctx context.Context, f *db.Function, file *db.File, root parser.Node, result *DetectResult) {
	ifs := root.FindAll("if_statement")
	for _, ifNode := range ifs {
		if ifNode.StartLine() < f.StartLine || ifNode.StartLine() > f.EndLine {
			continue
		}
		condition := ifNode.ChildByFieldName("condition")
		if condition == nil {
			continue
		}
		condText := condition.Text()
		varName := extractGuardedVariable(*condition)
		if varName == "" {
			continue
		}
		condPattern := classifyGuard(condText)
		if condPattern == "" {
			continue
		}

		consequence := ifNode.ChildByFieldName("consequence")
		scopeEnd := f.EndLine
		if consequence != nil {
			scopeEnd = consequence.EndLine()
		}

		locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: ifNode.StartLine()})
		props, _ := json.Marshal(map[string]interface{}{
			"variable":    varName,
			"condition":   condPattern,
			"scope_start": ifNode.StartLine(),
			"scope_end":   scopeEnd,
		})
		_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
			EventType:  "NULL_GUARD",
			EntityID:   f.ID,
			LocationID: locID,
			Properties: string(props),
		})
		if err == nil {
			result.EventsCreated++
		}
	}
}

func (d *NullGuardDetector) detectEarlyReturnGuards(ctx context.Context, f *db.Function, file *db.File, root parser.Node, result *DetectResult) {
	ifs := root.FindAll("if_statement")
	for _, ifNode := range ifs {
		if ifNode.StartLine() < f.StartLine || ifNode.StartLine() > f.EndLine {
			continue
		}
		condition := ifNode.ChildByFieldName("condition")
		if condition == nil {
			continue
		}
		condText := condition.Text()
		condText = strings.TrimSpace(condText)
		for strings.HasPrefix(condText, "(") && strings.HasSuffix(condText, ")") {
			condText = strings.TrimSpace(condText[1 : len(condText)-1])
		}

		var varName string
		if strings.HasPrefix(condText, "!") {
			varName = strings.TrimSpace(condText[1:])
		} else if strings.Contains(condText, "==") && (strings.Contains(condText, "NULL") || strings.Contains(condText, " 0")) {
			parts := strings.SplitN(condText, "==", 2)
			for _, p := range parts {
				p = strings.TrimSpace(p)
				p = strings.Trim(p, "()")
				if p != "NULL" && p != "0" && p != "((void *)0)" {
					varName = p
					break
				}
			}
		}
		if varName == "" {
			continue
		}

		consequence := ifNode.ChildByFieldName("consequence")
		if consequence == nil {
			continue
		}
		if !strings.Contains(consequence.Text(), "return") {
			continue
		}

		locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: ifNode.StartLine()})
		props, _ := json.Marshal(map[string]interface{}{
			"variable":    varName,
			"condition":   "EARLY_RETURN",
			"scope_start": ifNode.StartLine() + 1,
			"scope_end":   f.EndLine,
		})
		_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
			EventType:  "NULL_GUARD",
			EntityID:   f.ID,
			LocationID: locID,
			Properties: string(props),
		})
		if err == nil {
			result.EventsCreated++
		}
	}
}

func extractGuardedVariable(cond parser.Node) string {
	text := strings.TrimSpace(cond.Text())
	if text == "" {
		return ""
	}
	if strings.Contains(text, "==") {
		parts := strings.SplitN(text, "==", 2)
		for _, p := range parts {
			p = strings.TrimSpace(p)
			p = strings.Trim(p, "()")
			if p != "NULL" && p != "0" && p != "((void *)0)" {
				return p
			}
		}
	}
	if strings.Contains(text, "!=") {
		parts := strings.SplitN(text, "!=", 2)
		for _, p := range parts {
			p = strings.TrimSpace(p)
			p = strings.Trim(p, "()")
			if p != "NULL" && p != "0" && p != "((void *)0)" {
				return p
			}
		}
	}
	idents := cond.FindAll("identifier")
	for _, id := range idents {
		name := id.Text()
		if name != "NULL" {
			return name
		}
	}
	return ""
}

func classifyGuard(condText string) string {
	condText = strings.TrimSpace(condText)
	if strings.Contains(condText, "==") {
		if strings.Contains(condText, "NULL") || strings.Contains(condText, "0") {
			return "NULL_CHECK"
		}
	}
	if strings.Contains(condText, "!=") {
		if strings.Contains(condText, "NULL") || strings.Contains(condText, "0") {
			return "NULL_CHECK"
		}
	}
	return "TRUTH_CHECK"
}
