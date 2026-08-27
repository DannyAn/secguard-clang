package graph

import (
	"context"
	"os"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// forEachFile groups indexed functions by source file and invokes fn once per
// file with the file, its parsed root, and its functions. It mirrors the
// evidence package's helper of the same name: builders previously re-read and
// re-parsed each file (and re-ran whole-tree FindAll) once per function, which
// is O(functions × tree) on large codebases.
//
// A file that cannot be read or parsed is SKIPPED (its functions contribute no
// graph edges). For a security tool that is a silent false-negative, so each
// skip is logged as a warning rather than dropped without a trace.
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
				logger.Warn("graph: get file by id failed, skipping", "file_id", fid, "error", err)
			}
			continue
		}
		if file == nil {
			continue
		}
		source, err := readFile(file.Path)
		if err != nil {
			if logger != nil {
				logger.Warn("graph: read file failed, skipping", "file", file.Path, "error", err)
			}
			continue
		}
		tree, err := p.ParseCached(source, file.Path)
		if err != nil {
			if logger != nil {
				logger.Warn("graph: parse file failed, skipping", "file", file.Path, "error", err)
			}
			continue
		}
		fn(file, tree.RootNode(), byFile[fid])
	}
	return nil
}

// funcLineRange reports whether a line falls inside the function's range.
func funcLineRange(f *db.Function, line int) bool {
	return line >= f.StartLine && line <= f.EndLine
}
