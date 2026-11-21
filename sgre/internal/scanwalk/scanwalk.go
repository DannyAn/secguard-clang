// Package scanwalk provides the shared "read each indexed source file once,
// parse it, run the visitor, release the tree" loop used by the evidence and
// graph passes. It owns only file bytes/parse lifetime; the caller supplies the
// file selection and the visitor.
package scanwalk

import (
	"context"
	"os"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// Each invokes fn once per file with its parsed root and tree, releasing the
// tree immediately after fn returns. A missing/unreadable or unparseable file
// is skipped with a warning (the caller's prefix identifies the stage), which
// keeps a partial scan from silently looking complete.
func Each(ctx context.Context, p *parser.Parser, logger *log.Logger, prefix string, files []*db.File, fn func(file *db.File, root parser.Node, tree *parser.Tree)) error {
	for _, file := range files {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		source, err := os.ReadFile(file.Path)
		if err != nil {
			if logger != nil {
				logger.Warn(prefix+": read file failed, skipping", "file", file.Path, "error", err)
			}
			continue
		}
		tree, err := p.ParseCached(source, file.Path)
		if err != nil {
			if logger != nil {
				logger.Warn(prefix+": parse file failed, skipping", "file", file.Path, "error", err)
			}
			continue
		}
		func() {
			defer tree.Release()
			fn(file, tree.RootNode(), tree)
		}()
	}
	return nil
}
