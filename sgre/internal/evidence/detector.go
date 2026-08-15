package evidence

import (
	"context"
	"os"

	"github.com/DannyAn/secguard-clang/internal/db"
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
func forEachFile(ctx context.Context, store db.Store, p *parser.Parser, fn func(file *db.File, root parser.Node, funcs []*db.Function)) error {
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
		if err != nil || file == nil {
			continue
		}
		source, err := os.ReadFile(file.Path)
		if err != nil {
			continue
		}
		tree, err := p.ParseCached(source, file.Path)
		if err != nil {
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
