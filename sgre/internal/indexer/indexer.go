package indexer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type Indexer struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

type IndexResult struct {
	FilesIndexed     int   `json:"files_indexed"`
	FunctionsIndexed int   `json:"functions_indexed"`
	FilesSkipped     int   `json:"files_skipped"`
	DurationMs       int64 `json:"duration_ms"`
}

func NewIndexer(store db.Store, logger *log.Logger) *Indexer {
	return &Indexer{
		store:  store,
		parser: parser.NewParser(),
		logger: logger,
	}
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

	files, err := WalkCFiles(absPath)
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

	existing, _ := idx.store.GetFileByPath(ctx, filePath)
	var fileID int64
	if existing != nil && existing.Checksum == checksum {
		if idx.logger != nil {
			idx.logger.Debug("file unchanged, skipping", "file", filePath)
		}
		result.FilesIndexed++
		return nil
	}
	if existing != nil {
		idx.store.UpdateFileChecksum(ctx, existing.ID, checksum, loc)
		fileID = existing.ID
		// The file changed: drop the previously-indexed functions for it so the
		// re-index below does not leave stale duplicate rows (the DB has no
		// upsert-on-name for functions, only INSERT).
		if err := idx.store.DeleteFunctionsByFile(ctx, fileID); err != nil {
			return fmt.Errorf("delete stale functions: %w", err)
		}
	} else {
		fileID, err = idx.store.InsertFile(ctx, &db.File{
			Path:     filePath,
			Language: "c",
			Checksum: checksum,
			LOC:      loc,
		})
		if err != nil {
			return fmt.Errorf("insert file: %w", err)
		}
	}
	result.FilesIndexed++

	tree, err := idx.parser.Parse(source, filePath)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	defer tree.Close()

	if tree.HasError() {
		if idx.logger != nil {
			idx.logger.Warn("file has syntax errors, indexing partial AST", "file", filePath)
		}
	}

	root := tree.RootNode()
	funcNodes := root.FindAll("function_definition")

	for _, fnNode := range funcNodes {
		funcRecord := extractFunction(fnNode, fileID)
		if funcRecord.Name == "" {
			continue
		}
		_, err := idx.store.InsertFunction(ctx, funcRecord)
		if err != nil {
			if idx.logger != nil {
				idx.logger.Warn("failed to insert function", "name", funcRecord.Name, "error", err)
			}
			continue
		}
		result.FunctionsIndexed++
	}

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
	return strings.Count(string(data), "\n") + 1
}
