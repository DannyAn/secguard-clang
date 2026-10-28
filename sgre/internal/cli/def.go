package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/symbols"
)

const (
	defBodyMaxLines = 300
	defMaxDefs      = 5
	defMaxSymbols   = 16
)

var defSymbolRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type symbolDef struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	File      string `json:"file,omitempty"`
	Line      int    `json:"line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	Signature string `json:"signature,omitempty"`
	Type      string `json:"type,omitempty"`
	Body      string `json:"body,omitempty"`
	BodyError string `json:"body_error,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

type defSearch struct {
	Root     string `json:"root,omitempty"`
	Database bool   `json:"database"`
	Headers  int    `json:"headers,omitempty"`
}

type defResult struct {
	Symbol      string      `json:"symbol"`
	Found       bool        `json:"found"`
	External    bool        `json:"external,omitempty"`
	Definitions []symbolDef `json:"definitions"`
	Truncated   bool        `json:"truncated,omitempty"`
	Search      defSearch   `json:"search"`
	ElapsedMS   int64       `json:"elapsed_ms"`
}

type defBatchResult struct {
	Symbols   []string     `json:"symbols"`
	Results   []*defResult `json:"results"`
	Found     int          `json:"found"`
	ElapsedMS int64        `json:"elapsed_ms"`
}

type defOptions struct {
	Kind   string
	InFile string
	Root   string
	// macroIndex is built once for a multi-symbol batch so a batch of macros
	// does not re-walk every header per symbol.
	macroIndex *symbols.MacroIndex
}

func runDefCmd(ctx context.Context, args []string) int {
	dbPath, dbExplicit, remaining := parseDBFlag(args)
	symbolNames, opts, err := parseDefArgs(remaining)
	if err != nil {
		WriteErrorJSON(err.Error())
		return 1
	}
	if len(symbolNames) == 0 {
		WriteErrorJSON("def requires at least one symbol (e.g. 'secguard def ase_sa_str_connect')")
		return 1
	}
	dbPath, found := resolveExistingDBPath(dbExplicit, dbPath)
	if !found {
		WriteErrorJSON("no sgre.db found; run 'secguard scan <path>' first")
		return 1
	}
	d, err := db.OpenReadOnly(ctx, dbPath)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to open database: %v", err))
		return 1
	}
	defer d.Close()

	if opts.Root == "" {
		opts.Root = defRoot(ctx, d)
	}
	start := time.Now()
	if len(symbolNames) > 1 && (opts.Kind == "" || opts.Kind == "macro") {
		var extra []string
		if opts.InFile != "" {
			p := opts.InFile
			if !filepath.IsAbs(p) && opts.Root != "" {
				p = filepath.Join(opts.Root, p)
			}
			extra = append(extra, p)
		}
		opts.macroIndex = symbols.BuildMacroIndex(opts.Root, extra)
	}

	var out interface{}
	if len(symbolNames) == 1 {
		res, err := lookupSymbol(ctx, d, symbolNames[0], opts)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("symbol lookup failed: %v", err))
			return 1
		}
		res.ElapsedMS = time.Since(start).Milliseconds()
		out = res
	} else {
		batch := &defBatchResult{Symbols: symbolNames, Results: make([]*defResult, 0, len(symbolNames))}
		for _, name := range symbolNames {
			symStart := time.Now()
			res, err := lookupSymbol(ctx, d, name, opts)
			if err != nil {
				WriteErrorJSON(fmt.Sprintf("symbol lookup failed for %s: %v", name, err))
				return 1
			}
			res.ElapsedMS = time.Since(symStart).Milliseconds()
			if res.Found {
				batch.Found++
			}
			batch.Results = append(batch.Results, res)
		}
		batch.ElapsedMS = time.Since(start).Milliseconds()
		out = batch
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to serialize result: %v", err))
		return 1
	}
	return 0
}

func parseDefArgs(args []string) ([]string, defOptions, error) {
	var opts defOptions
	var names []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--kind" && i+1 < len(args):
			opts.Kind = args[i+1]
			i++
		case strings.HasPrefix(a, "--kind="):
			opts.Kind = strings.TrimPrefix(a, "--kind=")
		case a == "--in" && i+1 < len(args):
			opts.InFile = args[i+1]
			i++
		case strings.HasPrefix(a, "--in="):
			opts.InFile = strings.TrimPrefix(a, "--in=")
		case a == "--root" && i+1 < len(args):
			opts.Root = args[i+1]
			i++
		case strings.HasPrefix(a, "--root="):
			opts.Root = strings.TrimPrefix(a, "--root=")
		case strings.HasPrefix(a, "-"):
			return nil, opts, fmt.Errorf("unknown flag %q", a)
		default:
			if len(names) >= defMaxSymbols {
				return nil, opts, fmt.Errorf("def accepts at most %d symbols per call", defMaxSymbols)
			}
			if !defSymbolRe.MatchString(a) {
				return nil, opts, fmt.Errorf("invalid symbol %q (expected a C identifier)", a)
			}
			names = append(names, a)
		}
	}
	opts.Kind = strings.ToLower(strings.TrimSpace(opts.Kind))
	if opts.Kind == "auto" {
		opts.Kind = ""
	}
	switch opts.Kind {
	case "", "function", "declaration", "macro", "type", "variable":
	default:
		return nil, opts, fmt.Errorf("invalid --kind %q (expected auto|function|declaration|macro|type|variable)", opts.Kind)
	}
	return names, opts, nil
}

func lookupSymbol(ctx context.Context, d *sql.DB, symbol string, opts defOptions) (*defResult, error) {
	res := &defResult{Symbol: symbol, Definitions: []symbolDef{}}
	if opts.Root == "" {
		opts.Root = defRoot(ctx, d)
	}
	res.Search = defSearch{Root: opts.Root, Database: opts.Kind != "macro"}

	appendDefs := func(defs []symbolDef) {
		res.Definitions = append(res.Definitions, defs...)
	}

	if opts.Kind == "" || opts.Kind == "function" {
		defs, err := lookupFunctionDefs(ctx, d, symbol)
		if err != nil {
			return nil, err
		}
		appendDefs(defs)
		if len(res.Definitions) == 0 && opts.Kind == "" {
			decls, err := lookupDeclarationDefs(ctx, d, symbol)
			if err != nil {
				return nil, err
			}
			appendDefs(decls)
		}
	}
	if opts.Kind == "declaration" {
		decls, err := lookupDeclarationDefs(ctx, d, symbol)
		if err != nil {
			return nil, err
		}
		appendDefs(decls)
	}
	if (opts.Kind == "" && len(res.Definitions) == 0) || opts.Kind == "macro" {
		if opts.macroIndex != nil {
			res.Search.Headers = opts.macroIndex.Files()
			for _, m := range opts.macroIndex.Lookup(symbol) {
				appendDefs([]symbolDef{{
					Kind: "macro", Name: m.Name, File: m.File, Line: m.Line, EndLine: m.EndLine,
					Signature: m.Signature, Body: m.Body, Truncated: m.Truncated,
				}})
			}
		} else {
			defs, searched := lookupMacroDefs(symbol, opts.Root, opts.InFile)
			res.Search.Headers = searched
			appendDefs(defs)
		}
	}
	if (opts.Kind == "" && len(res.Definitions) == 0) || opts.Kind == "type" {
		defs, err := lookupTypeDefs(ctx, d, symbol)
		if err != nil {
			return nil, err
		}
		appendDefs(defs)
	}
	if (opts.Kind == "" && len(res.Definitions) == 0) || opts.Kind == "variable" {
		defs, err := lookupVariableDefs(ctx, d, symbol)
		if err != nil {
			return nil, err
		}
		appendDefs(defs)
	}

	res.Found = len(res.Definitions) > 0
	res.External = !res.Found
	if len(res.Definitions) > defMaxDefs {
		res.Definitions = res.Definitions[:defMaxDefs]
		res.Truncated = true
	}
	return res, nil
}

func lookupFunctionDefs(ctx context.Context, d *sql.DB, name string) ([]symbolDef, error) {
	rows, err := d.QueryContext(ctx, `
SELECT f.path, fn.name, fn.signature, fn.return_type, fn.start_line, fn.end_line
FROM functions fn JOIN files f ON f.id = fn.file_id
WHERE fn.name = ? ORDER BY f.path, fn.start_line`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var defs []symbolDef
	for rows.Next() {
		var path, sym, sig, ret string
		var start, end int
		if err := rows.Scan(&path, &sym, &sig, &ret, &start, &end); err != nil {
			return nil, err
		}
		body, truncated, berr := symbols.ReadLines(path, start, end, defBodyMaxLines)
		def := symbolDef{
			Kind: "function", Name: sym, File: path, Line: start, EndLine: end,
			Signature: sig, Type: ret, Body: body, Truncated: truncated,
		}
		if berr != nil {
			def.BodyError = berr.Error()
		}
		defs = append(defs, def)
	}
	return defs, rows.Err()
}

func lookupDeclarationDefs(ctx context.Context, d *sql.DB, name string) ([]symbolDef, error) {
	rows, err := d.QueryContext(ctx, `
SELECT f.path, d.name, d.signature, d.return_type, d.start_line
FROM function_declarations d JOIN files f ON f.id = d.file_id
WHERE d.name = ? ORDER BY f.path, d.start_line`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var defs []symbolDef
	for rows.Next() {
		var path, sym, sig, ret string
		var line int
		if err := rows.Scan(&path, &sym, &sig, &ret, &line); err != nil {
			return nil, err
		}
		defs = append(defs, symbolDef{
			Kind: "declaration", Name: sym, File: path, Line: line, EndLine: line,
			Signature: sig, Type: ret,
		})
	}
	return defs, rows.Err()
}

func lookupTypeDefs(ctx context.Context, d *sql.DB, name string) ([]symbolDef, error) {
	rows, err := d.QueryContext(ctx, `SELECT name, kind FROM types WHERE name = ?`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var defs []symbolDef
	for rows.Next() {
		var sym, kind string
		if err := rows.Scan(&sym, &kind); err != nil {
			return nil, err
		}
		defs = append(defs, symbolDef{Kind: "type", Name: sym, Type: kind})
	}
	return defs, rows.Err()
}

func lookupVariableDefs(ctx context.Context, d *sql.DB, name string) ([]symbolDef, error) {
	var defs []symbolDef
	rows, err := d.QueryContext(ctx, `
SELECT f.path, v.name, v.type, v.declaration_line
FROM variables v JOIN functions fn ON fn.id = v.function_id JOIN files f ON f.id = fn.file_id
WHERE v.name = ? ORDER BY f.path, v.declaration_line`, name)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var path, sym, typ string
		var line int
		if err := rows.Scan(&path, &sym, &typ, &line); err != nil {
			rows.Close()
			return nil, err
		}
		defs = append(defs, symbolDef{Kind: "variable", Name: sym, File: path, Line: line, EndLine: line, Type: typ})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	rows, err = d.QueryContext(ctx, `
SELECT f.path, v.name, v.type, v.declaration_line
FROM file_scope_variables v JOIN files f ON f.id = v.file_id
WHERE v.name = ? ORDER BY f.path, v.declaration_line`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var path, sym, typ string
		var line int
		if err := rows.Scan(&path, &sym, &typ, &line); err != nil {
			return nil, err
		}
		defs = append(defs, symbolDef{Kind: "variable", Name: sym, File: path, Line: line, EndLine: line, Type: typ})
	}
	return defs, rows.Err()
}

func lookupMacroDefs(name, root, inFile string) ([]symbolDef, int) {
	seen := map[string]bool{}
	var paths []string
	addPath := func(p string) {
		if p == "" {
			return
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return
		}
		if seen[abs] {
			return
		}
		seen[abs] = true
		paths = append(paths, abs)
	}
	if inFile != "" {
		p := inFile
		if !filepath.IsAbs(p) && root != "" {
			p = filepath.Join(root, p)
		}
		addPath(p)
	}
	if root != "" {
		for _, p := range symbols.HeaderFiles(root) {
			addPath(p)
		}
	}

	var defs []symbolDef
	for _, p := range paths {
		for _, m := range symbols.ScanMacrosInFile(p, name) {
			defs = append(defs, symbolDef{
				Kind: "macro", Name: m.Name, File: m.File, Line: m.Line, EndLine: m.EndLine,
				Signature: m.Signature, Body: m.Body, Truncated: m.Truncated,
			})
		}
	}
	return defs, len(paths)
}

func defRoot(ctx context.Context, d *sql.DB) string {
	rows, err := d.QueryContext(ctx, `SELECT path FROM files ORDER BY id`)
	if err != nil {
		return ""
	}
	defer rows.Close()
	var paths []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return ""
		}
		paths = append(paths, p)
	}
	return symbols.RootFor(paths)
}
