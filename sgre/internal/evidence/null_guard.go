package evidence

import (
	"context"
	"encoding/json"
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

	err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		ifs := root.FindAll("if_statement")
		whiles := root.FindAll("while_statement")
		fors := root.FindAll("for_statement")
		// Iterator-style guards live in loop conditions:
		//   while ((e = dictNext(di)) != NULL) { e->val; }
		// The loop body is only entered when the iterator returned non-null, so
		// a deref inside is guarded. if/while/for all expose a "condition" field.
		condNodes := append(append(append([]parser.Node{}, ifs...), whiles...), fors...)
		for _, f := range funcs {
			d.detectGuards(ctx, f, file, condNodes, &result)
			d.detectEarlyReturnGuards(ctx, f, file, ifs, &result)
		}
	})
	return result, err
}

func (d *NullGuardDetector) detectGuards(ctx context.Context, f *db.Function, file *db.File, ifs []parser.Node, result *DetectResult) {
	for _, ifNode := range ifs {
		if !funcLineRange(f, ifNode.StartLine()) {
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

		// if uses "consequence", while/for use "body"; either delimits the
		// guarded scope.
		scopeEnd := f.EndLine
		if consequence := ifNode.ChildByFieldName("consequence"); consequence != nil {
			scopeEnd = consequence.EndLine()
		} else if body := ifNode.ChildByFieldName("body"); body != nil {
			scopeEnd = body.EndLine()
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

func (d *NullGuardDetector) detectEarlyReturnGuards(ctx context.Context, f *db.Function, file *db.File, ifs []parser.Node, result *DetectResult) {
	for _, ifNode := range ifs {
		if !funcLineRange(f, ifNode.StartLine()) {
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
	for _, op := range []string{"==", "!="} {
		if strings.Contains(text, op) {
			parts := strings.SplitN(text, op, 2)
			for _, p := range parts {
				p = guardVarName(p)
				if p != "" && p != "NULL" && p != "0" && p != "((void *)0)" {
					return p
				}
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

// guardVarName normalises one operand of a null comparison: it trims
// parentheses and, for an assignment-in-condition (`(e = dictNext()) != NULL`),
// returns the assignment target `e` rather than the whole `e = dictNext()`.
func guardVarName(operand string) string {
	t := strings.TrimSpace(operand)
	for strings.HasPrefix(t, "(") && strings.HasSuffix(t, ")") {
		t = strings.TrimSpace(t[1 : len(t)-1])
	}
	if i := strings.Index(t, "="); i > 0 {
		t = strings.TrimSpace(t[:i])
	}
	t = strings.TrimPrefix(t, "*")
	return strings.TrimSpace(t)
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
