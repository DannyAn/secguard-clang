package graph

import (
	"context"
	"encoding/json"
	"os"
	"sort"

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

// nodesInRange returns the sub-slice of nodes whose StartLine is in
// [start, end]. nodes must be in non-decreasing StartLine order — root.FindAll
// emits nodes in document (pre-order) order, which for a single node kind is
// sorted by StartLine (an inner node always starts at or after its enclosing
// node). It replaces the previous O(functions × nodes) pattern where every
// function re-scanned the whole per-file node list, with a binary search per
// function.
func nodesInRange(nodes []parser.Node, start, end int) []parser.Node {
	lo := sort.Search(len(nodes), func(i int) bool { return nodes[i].StartLine() >= start })
	hi := sort.Search(len(nodes), func(i int) bool { return nodes[i].StartLine() > end })
	return nodes[lo:hi]
}

// warnEdge logs a graph edge/node write failure with the edge type, function,
// and error. The builders persist graph facts best-effort (a failed write must
// not abort the whole scan), but a silently swallowed write is an untraceable
// false-negative, so every failure is logged.
func warnEdge(logger *log.Logger, edgeType, function string, err error) {
	if logger != nil {
		logger.Warn("graph: edge write failed", "edge_type", edgeType, "function", function, "error", err)
	}
}

// marshalProps marshals graph edge/node properties to JSON. The property maps
// are all string/int typed, so a marshal failure is effectively impossible, but
// swallowing the error would silently write empty properties; log it and return
// "" instead.
func marshalProps(logger *log.Logger, edgeType string, props any) string {
	data, err := json.Marshal(props)
	if err != nil {
		if logger != nil {
			logger.Warn("graph: marshal props failed", "edge_type", edgeType, "error", err)
		}
		return ""
	}
	return string(data)
}
