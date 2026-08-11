package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/kongan/secguard-lite/internal/db"
	"github.com/kongan/secguard-lite/internal/log"
	"github.com/kongan/secguard-lite/internal/parser"
)

type RaceConditionDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewRaceConditionDetector(store db.Store, p *parser.Parser, logger *log.Logger) *RaceConditionDetector {
	return &RaceConditionDetector{store: store, parser: p, logger: logger}
}

func (d *RaceConditionDetector) Name() string { return "race_condition" }

func (d *RaceConditionDetector) Domain() string { return "concurrency" }

func (d *RaceConditionDetector) Capabilities() []string {
	return []string{"toctou-filesystem", "toctou-shared-state"}
}

var checkFunctions = map[string]bool{
	"access": true, "stat": true, "lstat": true, "faccessat": true,
}

var useFunctions = map[string]bool{
	"fopen": true, "open": true, "creat": true, "freopen": true, "openat": true,
}

func (d *RaceConditionDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return result, fmt.Errorf("race_condition: list functions: %w", err)
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
		tree, err := d.parser.Parse(source, file.Path)
		if err != nil {
			continue
		}
		root := tree.RootNode()

		for _, ifStmt := range root.FindAll("if_statement") {
			if ifStmt.StartLine() < f.StartLine || ifStmt.StartLine() > f.EndLine {
				continue
			}
			cond := ifStmt.ChildByFieldName("condition")
			if cond == nil {
				continue
			}
			checkCall := d.findCheckCall(*cond)
			if checkCall == nil {
				continue
			}
			checkArg := extractFirstArg(*checkCall)
			if checkArg == "" {
				continue
			}
			consequence := ifStmt.ChildByFieldName("consequence")
			if consequence == nil {
				continue
			}
			for _, useCall := range consequence.FindAll("call_expression") {
				useName := extractCallName(useCall)
				if !useFunctions[useName] {
					continue
				}
				useArg := extractFirstArg(useCall)
				if useArg == checkArg {
					locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: checkCall.StartLine(), Column: checkCall.StartColumn()})
					props, _ := json.Marshal(map[string]string{
						"check_function": extractCallName(*checkCall),
						"use_function":   useName,
						"path_arg":       checkArg,
						"category":       "toctou",
					})
					_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
						EventType:  "RACE_CONDITION",
						EntityID:   f.ID,
						LocationID: locID,
						Properties: string(props),
					})
					if err == nil {
						result.EventsCreated++
					}
					break
				}
			}
		}

		d.detectLockUnlockPattern(ctx, root, f, file, &result)

		tree.Close()
	}

	return result, nil
}

func (d *RaceConditionDetector) findCheckCall(cond parser.Node) *parser.Node {
	for _, call := range cond.FindAll("call_expression") {
		if checkFunctions[extractCallName(call)] {
			return &call
		}
	}
	return nil
}

func (d *RaceConditionDetector) detectLockUnlockPattern(ctx context.Context, root parser.Node, f *db.Function, file *db.File, result *DetectResult) {
	lockLines := make(map[int]string)
	unlockLines := make(map[int]string)
	for _, call := range root.FindAll("call_expression") {
		if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
			continue
		}
		callName := extractCallName(call)
		if callName == "pthread_mutex_lock" {
			mutexArg := extractFirstArg(call)
			lockLines[call.StartLine()] = mutexArg
		}
		if callName == "pthread_mutex_unlock" {
			mutexArg := extractFirstArg(call)
			unlockLines[call.StartLine()] = mutexArg
		}
	}

	lockLine := 0
	unlockLine := 0
	var mutexName string
	for ll, mname := range lockLines {
		for ul, uname := range unlockLines {
			if ul > ll && mname == uname {
				if lockLine == 0 || ll < lockLine {
					lockLine = ll
					unlockLine = ul
					mutexName = mname
				}
			}
		}
	}
	if lockLine == 0 {
		return
	}

	for _, assign := range root.FindAll("assignment_expression") {
		if assign.StartLine() <= unlockLine || assign.StartLine() > f.EndLine {
			continue
		}
		text := assign.Text()
		if strings.Contains(text, "g_") || strings.Contains(text, "global") || strings.Contains(text, "shared") {
			locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: assign.StartLine(), Column: assign.StartColumn()})
			props, _ := json.Marshal(map[string]string{
				"mutex":       mutexName,
				"lock_line":   fmt.Sprintf("%d", lockLine),
				"unlock_line": fmt.Sprintf("%d", unlockLine),
				"category":    "toctou_shared_state",
			})
			_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
				EventType:  "RACE_CONDITION",
				EntityID:   f.ID,
				LocationID: locID,
				Properties: string(props),
			})
			if err == nil {
				result.EventsCreated++
			}
			break
		}
	}
}

func extractFirstArg(call parser.Node) string {
	for _, child := range call.NamedChildren() {
		if child.Kind() == "argument_list" {
			args := child.NamedChildren()
			if len(args) > 0 {
				return args[0].Text()
			}
		}
	}
	return ""
}
