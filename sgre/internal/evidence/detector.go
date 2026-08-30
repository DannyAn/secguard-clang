package evidence

import (
	"context"
	"encoding/json"
	"os"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type Detector interface {
	Name() string
	Detect(ctx context.Context) (DetectResult, error)
}

type DetectResult struct {
	EventsCreated int
	Summary       string
}

type DomainAware interface {
	Domain() string
	Capabilities() []string
}

// forEachFile groups the indexed functions by source file and invokes fn once
// per file with the file, its parsed root, and the functions it contains.
//
// Detectors previously iterated functions and re-read + re-parsed each file
// once per function, then ran root.FindAll(...) (a whole-tree traversal) once
// per function. On a codebase with F functions per file that is O(F) reads,
// parses and traversals per file; this collapses all three to one per file.
// On redis (11225 functions over 786 files) the dereference detector alone went
// from ~9 minutes of FindAll traversals to a single traversal per file.
//
// A file that cannot be read or parsed is SKIPPED (its functions emit no events
// for any detector). For a security tool that is a silent false-negative, so
// each skip is logged as a warning rather than dropped without a trace.
func forEachFile(ctx context.Context, store db.Store, p *parser.Parser, logger *log.Logger, fn func(file *db.File, root parser.Node, funcs []*db.Function)) error {
	funcs, err := store.ListFunctions(ctx)
	if err != nil {
		return err
	}

	byFile := make(map[int64][]*db.Function, 128)
	var order []int64
	for _, f := range funcs {
		if _, seen := byFile[f.FileID]; !seen {
			order = append(order, f.FileID)
		}
		byFile[f.FileID] = append(byFile[f.FileID], f)
	}

	for _, fid := range order {
		file, err := store.GetFileByID(ctx, fid)
		if err != nil {
			if logger != nil {
				logger.Warn("evidence: get file by id failed, skipping", "file_id", fid, "error", err)
			}
			continue
		}
		if file == nil {
			continue
		}
		source, err := os.ReadFile(file.Path)
		if err != nil {
			if logger != nil {
				logger.Warn("evidence: read file failed, skipping", "file", file.Path, "error", err)
			}
			continue
		}
		tree, err := p.ParseCached(source, file.Path)
		if err != nil {
			if logger != nil {
				logger.Warn("evidence: parse file failed, skipping", "file", file.Path, "error", err)
			}
			continue
		}
		fn(file, tree.RootNode(), byFile[fid])
	}
	return nil
}

// funcLineRange reports whether a node's start line falls inside the function's
// [StartLine, EndLine] range.
func funcLineRange(f *db.Function, line int) bool {
	return line >= f.StartLine && line <= f.EndLine
}

// emitEvent inserts a location and a security event, logging (and returning
// false) on any failure. This replaces the detectors' previous pattern of
// swallowing both InsertLocation (whose failure yielded locID=0 and a foreign-key
// violation that silently dropped the event) and InsertEvent errors, so a DB
// write failure is surfaced instead of silently losing a finding.
func emitEvent(ctx context.Context, store db.Store, logger *log.Logger, eventType string, entityID int64, loc *db.Location, props any) bool {
	locID, err := store.InsertLocation(ctx, loc)
	if err != nil {
		if logger != nil {
			logger.Warn("insert location failed", "event_type", eventType, "error", err)
		}
		return false
	}
	data, err := json.Marshal(props)
	if err != nil {
		if logger != nil {
			logger.Warn("marshal event properties failed", "event_type", eventType, "error", err)
		}
		return false
	}
	if _, err := store.InsertEvent(ctx, &db.SecurityEvent{
		EventType:  eventType,
		EntityID:   entityID,
		LocationID: locID,
		Properties: string(data),
	}); err != nil {
		if logger != nil {
			logger.Warn("insert event failed", "event_type", eventType, "error", err)
		}
		return false
	}
	return true
}
