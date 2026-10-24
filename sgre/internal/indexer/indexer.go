package indexer

import (
	"bytes"
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
	store        db.Store
	parser       *parser.Parser
	logger       *log.Logger
	excludeDirs  []string
	excludePaths []string
}

type IndexResult struct {
	FilesIndexed     int `json:"files_indexed"`
	FunctionsIndexed int `json:"functions_indexed"`
	FilesSkipped     int `json:"files_skipped"`
	// LinesOfCode is the summed line count of every file this run walked
	// (skipped-but-unchanged files included), so a report header can state the
	// scanned scale without a second pass over the files table.
	LinesOfCode int   `json:"lines_of_code"`
	DurationMs  int64 `json:"duration_ms"`
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

// SetExcludePaths sets the directory paths pruned during the walk (resolved
// against the scan target at walk time). A nil or empty slice excludes nothing
// by path; it never affects the basename exclusions.
func (idx *Indexer) SetExcludePaths(paths []string) {
	idx.excludePaths = paths
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

	files, err := WalkCFiles(absPath, idx.excludeDirs, idx.excludePaths, idx.logger)
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
	result.LinesOfCode += loc

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
	declNodes := root.FindAll("declaration")
	fileScopeVars := extractFileScopeVariables(root)

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
			if err := tx.DeleteFunctionDeclarationsByFile(ctx, existing.ID); err != nil {
				return fmt.Errorf("delete stale function declarations: %w", err)
			}
			if err := tx.DeleteFileScopeVariablesByFile(ctx, existing.ID); err != nil {
				return fmt.Errorf("delete stale file-scope variables: %w", err)
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
		definedNames := make(map[string]bool)
		for _, fnNode := range funcNodes {
			funcRecord := extractFunction(fnNode, fileID)
			if funcRecord.Name == "" {
				continue
			}
			if _, err := tx.InsertFunction(ctx, funcRecord); err != nil {
				return fmt.Errorf("insert function %s: %w", funcRecord.Name, err)
			}
			definedNames[funcRecord.Name] = true
			inserted++
		}
		// Keep prototypes out of functions: it is the definition table every
		// graph/detector/planner consumer treats as a body-bearing callable.
		// Declarations live separately and are consumed only for external
		// return-type filtering.
		for _, declNode := range declNodes {
			funcRecord := extractFunction(declNode, fileID)
			if funcRecord.Name == "" || definedNames[funcRecord.Name] {
				continue
			}
			if _, err := tx.InsertFunctionDeclaration(ctx, &db.FunctionDeclaration{
				FileID:     fileID,
				Name:       funcRecord.Name,
				Signature:  funcRecord.Signature,
				ReturnType: funcRecord.ReturnType,
				StartLine:  funcRecord.StartLine,
			}); err != nil {
				return fmt.Errorf("insert function declaration %s: %w", funcRecord.Name, err)
			}
		}
		// File-scope variables feed the interprocedural alias graph's global
		// alias resolution: `g = p` is a global alias only when g is a declared
		// file-scope name, and a `static` g (one object per file) is keyed apart
		// from an `extern` g (one object program-wide).
		for _, v := range fileScopeVars {
			v.FileID = fileID
			if _, err := tx.InsertFileScopeVariable(ctx, v); err != nil {
				return fmt.Errorf("insert file-scope variable %s: %w", v.Name, err)
			}
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

// extractFileScopeVariables returns the file-scope (translation-unit-level)
// variable declarations, distinguishing `static` (internal linkage, one object
// per file) from `extern` (external linkage, one object program-wide — the
// default for a non-static file-scope declaration). Function prototypes and
// typedefs are not variables and are skipped. Local declarations (inside a
// function body) are excluded by the parent-kind filter.
func extractFileScopeVariables(root parser.Node) []*db.FileScopeVariable {
	var out []*db.FileScopeVariable
	for _, decl := range root.FindAll("declaration") {
		parent := decl.Parent()
		if parent == nil || parent.Kind() != "translation_unit" {
			continue
		}
		storage := "extern"
		for _, c := range decl.NamedChildren() {
			if c.Kind() != "storage_class_specifier" {
				continue
			}
			switch c.Text() {
			case "static":
				storage = "static"
			case "typedef":
				storage = "typedef"
			}
		}
		if storage == "typedef" {
			continue
		}
		dec := decl.ChildByFieldName("declarator")
		if dec == nil {
			continue
		}
		name := declaredVarName(*dec)
		if name == "" {
			continue // function prototype or unrecognized declarator
		}
		typ := ""
		if t := decl.ChildByFieldName("type"); t != nil {
			typ = t.Text()
		}
		out = append(out, &db.FileScopeVariable{
			Name: name, Type: typ, StorageClass: storage,
			DeclarationLine: decl.StartLine(), IsPointer: fileScopeVarIsPointer(dec.Text()),
		})
	}
	return out
}

// declaredVarName returns the bare identifier declared by a declarator node,
// or "" when the declarator is a function (a prototype, not a variable). It
// recurses through pointer/array/parenthesized/init declarators to the
// innermost identifier.
func declaredVarName(n parser.Node) string {
	switch n.Kind() {
	case "identifier":
		return n.Text()
	case "function_declarator":
		return ""
	case "init_declarator":
		if dec := n.ChildByFieldName("declarator"); dec != nil {
			return declaredVarName(*dec)
		}
		return ""
	case "pointer_declarator", "array_declarator", "parenthesized_declarator":
		for _, c := range n.NamedChildren() {
			if name := declaredVarName(c); name != "" {
				return name
			}
		}
		return ""
	}
	return ""
}

func fileScopeVarIsPointer(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), "*")
}

func extractFunction(node parser.Node, fileID int64) *db.Function {
	fn := &db.Function{
		FileID:    fileID,
		StartLine: node.StartLine(),
		EndLine:   node.EndLine(),
	}

	isPointer := false
	for _, child := range node.NamedChildren() {
		switch child.Kind() {
		case "primitive_type", "type_identifier", "sized_type_specifier",
			"struct_specifier", "union_specifier", "enum_specifier":
			// Take the LAST type specifier, not the first: a function attribute
			// macro in return position (`NO_HCFI uint32_t f(...)`) parses the
			// macro as an extra type_identifier, and storing the first one would
			// record "NO_HCFI" instead of "uint32_t".
			fn.ReturnType = child.Text()
		case "ERROR":
			// tree-sitter recovers `NO_HCFI uint32_t f(...)` by putting the REAL
			// type (`uint32_t`) into an ERROR node after the macro (which it
			// misparsed as a type_identifier). Recover the type from there.
			if t := lastIdentifierInError(child); t != "" {
				fn.ReturnType = t
			}
		case "function_declarator":
			extractDeclarator(child, fn)
		case "pointer_declarator":
			// The declarator carries one or more `*` (`char *f`, `char **f`,
			// `sds *f` for a pointer-to-pointer return): the return type is a
			// pointer at each level. Recurse through nested pointer_declarators
			// (tree-sitter nests one per `*`) to the function_declarator and
			// record every level, so `char **` is never mistaken for `char *` or
			// scalar `char`.
			isPointer = true
			depth := 0
			cur := child
			for {
				depth++
				var fnDecl, inner parser.Node
				for _, grandchild := range cur.NamedChildren() {
					switch grandchild.Kind() {
					case "function_declarator":
						fnDecl = grandchild
					case "pointer_declarator":
						inner = grandchild
					}
				}
				if fnDecl.Kind() != "" {
					extractDeclarator(fnDecl, fn)
					break
				}
				if inner.Kind() == "" {
					break
				}
				cur = inner
			}
			fn.ReturnType += strings.Repeat("*", depth)
		case "storage_class_specifier":
			if child.Text() == "static" {
				fn.IsStatic = true
			}
		}
	}

	if isPointer && !strings.HasSuffix(fn.ReturnType, "*") {
		fn.ReturnType += "*"
	}

	return fn
}

// lastIdentifierInError returns the last identifier-like token inside an ERROR
// node — the real return type that tree-sitter recovered after misparsing a
// function-attribute macro (`NO_HCFI`) as a type_identifier.
func lastIdentifierInError(err parser.Node) string {
	var last string
	for _, c := range err.NamedChildren() {
		switch c.Kind() {
		case "identifier", "type_identifier", "primitive_type", "sized_type_specifier":
			last = c.Text()
		}
	}
	return last
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
