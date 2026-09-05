package indexer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type Indexer struct {
	store       db.Store
	parser      *parser.Parser
	logger      *log.Logger
	excludeDirs []string
}

type IndexResult struct {
	FilesIndexed     int   `json:"files_indexed"`
	FunctionsIndexed int   `json:"functions_indexed"`
	FilesSkipped     int   `json:"files_skipped"`
	DurationMs       int64 `json:"duration_ms"`
}

func NewIndexer(store db.Store, logger *log.Logger) *Indexer {
	return &Indexer{
		store:       store,
		parser:      parser.NewParser(),
		logger:      logger,
		excludeDirs: DefaultExcludeDirs,
	}
}

// SetExcludeDirs overrides the directory basenames skipped during the walk.
// An empty slice means "exclude nothing"; a nil slice keeps the default set.
func (idx *Indexer) SetExcludeDirs(dirs []string) {
	if dirs == nil {
		idx.excludeDirs = DefaultExcludeDirs
		return
	}
	idx.excludeDirs = dirs
}

func (idx *Indexer) Index(ctx context.Context, targetPath string) (*IndexResult, error) {
	result := &IndexResult{}

	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		return nil, fmt.Errorf("indexer: resolve path: %w", err)
	}
	if _, err := os.Stat(absPath); err != nil {
		return nil, fmt.Errorf("indexer: target path: %w", err)
	}

	files, err := WalkCFiles(absPath, idx.excludeDirs, idx.logger)
	if err != nil {
		return nil, fmt.Errorf("indexer: walk files: %w", err)
	}

	for _, filePath := range files {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		if err := idx.indexFile(ctx, filePath, result); err != nil {
			if idx.logger != nil {
				idx.logger.Warn("failed to index file", "file", filePath, "error", err)
			}
			result.FilesSkipped++
		}
	}

	return result, nil
}

func (idx *Indexer) indexFile(ctx context.Context, filePath string, result *IndexResult) error {
	source, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	checksum := computeChecksum(source)
	loc := countLines(source)

	existing, err := idx.store.GetFileByPath(ctx, filePath)
	if err != nil {
		return fmt.Errorf("get file: %w", err)
	}
	if existing != nil && existing.Checksum == checksum {
		if idx.logger != nil {
			idx.logger.Debug("file unchanged, skipping", "file", filePath)
		}
		result.FilesIndexed++
		return nil
	}

	// Parse outside the transaction so the write lock is held only for the file/
	// function writes below, never across the (potentially long) parse.
	tree, err := idx.parser.Parse(source, filePath)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	defer tree.Close()

	// tree-sitter reports ERROR/MISSING nodes for constructs the C grammar cannot
	// fully resolve — most commonly calling-convention macros like `CJSON_CDECL`
	// in function-pointer typedefs and preprocessor-guarded declarations. These do
	// not mean the file is malformed or that the AST is unusable; indexing proceeds
	// on the best-effort tree either way. Genuine parse failures surface separately
	// via the "failed to index file" warning in Index.
	if tree.HasError() {
		if idx.logger != nil {
			idx.logger.Debug("parse produced error nodes (typically preprocessor/macro artifacts); indexing best-effort AST", "file", filePath)
		}
	}

	root := tree.RootNode()
	funcNodes := root.FindAll("function_definition")

	// Rebuild the file's rows atomically. The checksum update (or insert) plus
	// the stale-function delete plus the function inserts must commit together:
	// otherwise a crash between the checksum write and the function inserts
	// leaves "checksum already new, functions incomplete", which the
	// unchanged-file skip above would then treat as up-to-date forever — a
	// permanent false negative with no self-heal.
	var inserted int
	err = idx.store.WithTx(ctx, func(tx db.Store) error {
		var fileID int64
		if existing != nil {
			if err := tx.UpdateFileChecksum(ctx, existing.ID, checksum, loc); err != nil {
				return fmt.Errorf("update file checksum: %w", err)
			}
			// The file changed: drop the previously-indexed functions for it so
			// the re-index does not leave stale duplicate rows (the DB has no
			// upsert-on-name for functions, only INSERT).
			if err := tx.DeleteFunctionsByFile(ctx, existing.ID); err != nil {
				return fmt.Errorf("delete stale functions: %w", err)
			}
			fileID = existing.ID
		} else {
			id, err := tx.InsertFile(ctx, &db.File{
				Path:     filePath,
				Language: "c",
				Checksum: checksum,
				LOC:      loc,
			})
			if err != nil {
				return fmt.Errorf("insert file: %w", err)
			}
			fileID = id
		}
		for _, fnNode := range funcNodes {
			funcRecord := extractFunction(fnNode, fileID)
			if funcRecord.Name == "" {
				continue
			}
			if _, err := tx.InsertFunction(ctx, funcRecord); err != nil {
				return fmt.Errorf("insert function %s: %w", funcRecord.Name, err)
			}
			inserted++
		}
		return nil
	})
	if err != nil {
		return err
	}

	result.FilesIndexed++
	result.FunctionsIndexed += inserted
	return nil
}

func extractFunction(node parser.Node, fileID int64) *db.Function {
	fn := &db.Function{
		FileID:    fileID,
		StartLine: node.StartLine(),
		EndLine:   node.EndLine(),
	}

	for _, child := range node.NamedChildren() {
		switch child.Kind() {
		case "primitive_type", "type_identifier", "sized_type_specifier":
			if fn.ReturnType == "" {
				fn.ReturnType = child.Text()
			}
		case "function_declarator":
			extractDeclarator(child, fn)
		case "pointer_declarator":
			for _, grandchild := range child.NamedChildren() {
				if grandchild.Kind() == "function_declarator" {
					extractDeclarator(grandchild, fn)
				}
			}
		case "storage_class_specifier":
			if child.Text() == "static" {
				fn.IsStatic = true
			}
		}
	}

	return fn
}

func extractDeclarator(node parser.Node, fn *db.Function) {
	for _, child := range node.NamedChildren() {
		switch child.Kind() {
		case "identifier":
			fn.Name = child.Text()
		case "parameter_list":
			fn.Signature = buildSignature(node)
		}
	}
	if fn.Signature == "" {
		fn.Signature = fn.Name + "()"
	}
}

func buildSignature(node parser.Node) string {
	return node.Text()
}

func computeChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func countLines(data []byte) int {
	return bytes.Count(data, []byte{'\n'}) + 1
}
