// Package repofacts builds the tree-wide declaration facts a detector needs to
// resolve a symbol declared in ANOTHER file — a header, which is where real C
// code keeps every struct, typedef, macro and extern array.
//
// The motivating failure class: a detector cached `root.FindAll(...)` of the
// file it was analyzing, so `p->svr[p->idx]` (struct in a header) resolved no
// capacity, `g_buf[256]` (declared in a header) resolved no size, and the
// detection silently vanished. Same-file fixtures passed, production produced
// zero candidates. This package is the single tree-wide source of those facts;
// per-file data stays the fast path, this is the fallback.
package repofacts

import (
	"context"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// FieldFact is one struct/union member.
type FieldFact struct {
	Name    string
	Type    string
	Pointer bool
	Array   bool
	Count   int
	Symbol  string
}

// GlobalArray is a file-scope array declaration (definition or extern).
type GlobalArray struct {
	Name   string
	Type   string
	Count  int
	Symbol string
}

// Facts is the immutable tree-wide fact set. Accessors are safe for concurrent
// use; the zero value answers "unknown" to every query.
type Facts struct {
	Macros map[string]int

	structs map[string]map[string]FieldFact
	fields  map[string][]FieldFact
	globals map[string][]GlobalArray
}

// Build walks every indexed file once and returns the aggregated facts.
// Conflicting definitions of the same name are dropped (a guessed value is worse
// than an unknown one).
func Build(ctx context.Context, store db.Store, p *parser.Parser, logger *log.Logger) (*Facts, error) {
	f := &Facts{
		Macros:  map[string]int{},
		structs: map[string]map[string]FieldFact{},
		fields:  map[string][]FieldFact{},
		globals: map[string][]GlobalArray{},
	}
	type fileNode struct {
		path string
		root parser.Node
	}
	var trees []fileNode

	// Pass 1: collect every parse tree and the tree-wide macro values.
	conflict := map[string]bool{}
	err := eachIndexedFile(ctx, store, p, logger, func(file *db.File, root parser.Node) {
		trees = append(trees, fileNode{path: file.Path, root: root})
		for name, v := range parser.CollectMacroValues(root) {
			if prev, ok := f.Macros[name]; ok && prev != v {
				conflict[name] = true
				continue
			}
			f.Macros[name] = v
		}
	})
	if err != nil {
		return nil, err
	}
	for name := range conflict {
		delete(f.Macros, name)
	}

	// Pass 2: layouts and file-scope arrays, with macro counts resolved.
	structCounts := map[string]map[string]map[int]bool{}
	structSymbols := map[string]map[string]string{}
	rawFields := map[string][]FieldFact{}
	globalCounts := map[string]map[int]bool{}
	globalSymbols := map[string]string{}
	globalTypes := map[string]string{}
	for _, tn := range trees {
		for _, kind := range []string{"struct_specifier", "union_specifier"} {
			for _, ss := range tn.root.FindAll(kind) {
				if ss.FindFirst("field_declaration_list") == nil {
					continue
				}
				keys := typeKeys(ss)
				if len(keys) == 0 {
					continue
				}
				for _, fd := range ss.FindAll("field_declaration") {
					typ := typeSpelling(fd)
					for _, ff := range fieldFacts(fd, typ, f.Macros) {
						for _, key := range keys {
							if structCounts[key] == nil {
								structCounts[key] = map[string]map[int]bool{}
							}
							if structSymbols[key] == nil {
								structSymbols[key] = map[string]string{}
							}
							if ff.Array {
								if structCounts[key][ff.Name] == nil {
									structCounts[key][ff.Name] = map[int]bool{}
								}
								structCounts[key][ff.Name][ff.Count] = true
								if ff.Symbol != "" {
									structSymbols[key][ff.Name] = ff.Symbol
								}
							}
						}
						rawFields[ff.Name] = append(rawFields[ff.Name], ff)
					}
				}
			}
		}
		for _, decl := range tn.root.FindAll("declaration") {
			if insideFunction(decl) {
				continue
			}
			typ := typeSpelling(decl)
			for _, ad := range decl.FindAll("array_declarator") {
				name := declaratorName(ad)
				if name == "" {
					continue
				}
				count, symbol, ok := arrayCapacity(ad, f.Macros)
				if !ok {
					continue
				}
				if globalCounts[name] == nil {
					globalCounts[name] = map[int]bool{}
				}
				globalCounts[name][count] = true
				globalTypes[name] = typ
				if symbol != "" {
					globalSymbols[name] = symbol
				}
			}
		}
	}

	// Finalize struct layouts: a field with conflicting counts inside one tag is
	// ambiguous and is left unresolved.
	for tag, fields := range structCounts {
		if f.structs[tag] == nil {
			f.structs[tag] = map[string]FieldFact{}
		}
		for name, set := range fields {
			if len(set) != 1 {
				continue
			}
			fact := FieldFact{Name: name, Array: true}
			for n := range set {
				fact.Count = n
			}
			fact.Symbol = structSymbols[tag][name]
			f.structs[tag][name] = fact
		}
	}
	// Finalize the by-name fallback: keep only facts that agree on shape+count.
	for name, list := range rawFields {
		first := list[0]
		agree := true
		for _, other := range list[1:] {
			if other.Pointer != first.Pointer || other.Array != first.Array || (other.Array && other.Count != first.Count) {
				agree = false
				break
			}
		}
		if agree {
			f.fields[name] = []FieldFact{first}
		} else {
			f.fields[name] = list
		}
	}
	for name, set := range globalCounts {
		if len(set) != 1 {
			continue
		}
		g := GlobalArray{Name: name, Type: globalTypes[name], Symbol: globalSymbols[name]}
		for n := range set {
			g.Count = n
		}
		f.globals[name] = []GlobalArray{g}
	}
	return f, nil
}

// MacroValue resolves an object-like macro tree-wide.
func (f *Facts) MacroValue(name string) (int, bool) {
	if f == nil {
		return 0, false
	}
	v, ok := f.Macros[strings.TrimSpace(name)]
	return v, ok
}

// FieldByTag resolves a member of a specific struct tag / typedef alias. It is
// the precise lookup: two structs that reuse a field name cannot shadow it.
func (f *Facts) FieldByTag(tag, field string) (FieldFact, bool) {
	if f == nil {
		return FieldFact{}, false
	}
	fields := f.structs[strings.TrimSpace(tag)]
	if fields == nil {
		return FieldFact{}, false
	}
	ff, ok := fields[strings.TrimSpace(field)]
	return ff, ok
}

// FieldByName is the fallback used when the struct tag cannot be resolved. It
// answers only when every declaration of the name agrees (unambiguous).
func (f *Facts) FieldByName(field string) (FieldFact, bool) {
	if f == nil {
		return FieldFact{}, false
	}
	list := f.fields[strings.TrimSpace(field)]
	if len(list) != 1 {
		return FieldFact{}, false
	}
	return list[0], true
}

// GlobalArray resolves a file-scope array's declared capacity.
func (f *Facts) GlobalArray(name string) (GlobalArray, bool) {
	if f == nil {
		return GlobalArray{}, false
	}
	list := f.globals[strings.TrimSpace(name)]
	if len(list) != 1 {
		return GlobalArray{}, false
	}
	return list[0], true
}

// eachIndexedFile visits every indexed file with its parsed root, logging and
// skipping unreadable/unparsable files instead of aborting the whole census.
func eachIndexedFile(ctx context.Context, store db.Store, p *parser.Parser, logger *log.Logger, fn func(*db.File, parser.Node)) error {
	files, err := store.ListFiles(ctx)
	if err != nil {
		return fmt.Errorf("repofacts: list files: %w", err)
	}
	for _, file := range files {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		source, err := readFile(file.Path)
		if err != nil {
			if logger != nil {
				logger.Warn("repofacts: read file failed, skipping", "file", file.Path, "error", err)
			}
			continue
		}
		tree, err := p.ParseCached(source, file.Path)
		if err != nil {
			if logger != nil {
				logger.Warn("repofacts: parse file failed, skipping", "file", file.Path, "error", err)
			}
			continue
		}
		fn(file, tree.RootNode())
	}
	return nil
}
