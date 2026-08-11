package evidence

import (
	"context"
	"os"
	"strings"

	"github.com/kongan/secguard-lite/internal/db"
	"github.com/kongan/secguard-lite/internal/parser"
)

type FuncSummary struct {
	ParamDirectFrees map[int]bool
	ParamFieldFrees  map[int][]string
	GlobalFrees      []string
	ReturnStores     []string
}

type summaryMap map[string]*FuncSummary

func buildFuncSummaries(ctx context.Context, store db.Store, p *parser.Parser) summaryMap {
	summaries := make(summaryMap)

	funcs, err := store.ListFunctions(ctx)
	if err != nil {
		return summaries
	}

	for _, f := range funcs {
		file, _ := store.GetFileByID(ctx, f.FileID)
		if file == nil {
			continue
		}
		source, err := os.ReadFile(file.Path)
		if err != nil {
			continue
		}
		tree, err := p.Parse(source, file.Path)
		if err != nil {
			continue
		}
		root := tree.RootNode()

		params := extractFunctionParams(root, f.StartLine)

		s := &FuncSummary{
			ParamDirectFrees: make(map[int]bool),
			ParamFieldFrees:  make(map[int][]string),
		}

		for _, call := range root.FindAll("call_expression") {
			if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
				continue
			}
			callName := extractCallName(call)
			if callName != "free" {
				continue
			}
			args := getCallArgs(call)
			if len(args) == 0 {
				continue
			}
			arg := args[0]

			if arg.Kind() == "identifier" {
				for idx, pn := range params {
					if pn == arg.Text() {
						s.ParamDirectFrees[idx] = true
					}
				}
			}

			if arg.Kind() == "field_expression" {
				baseVar, fieldName := extractFieldAccess(arg)
				for idx, pn := range params {
					if pn == baseVar && fieldName != "" {
						s.ParamFieldFrees[idx] = append(s.ParamFieldFrees[idx], fieldName)
					}
				}
			}

			globalName := extractGlobalFromArrayAccess(arg)
			if globalName != "" && !contains(s.GlobalFrees, globalName) {
				s.GlobalFrees = append(s.GlobalFrees, globalName)
			}
		}

		s.ReturnStores = findReturnStores(root, f)

		if len(s.ParamDirectFrees) > 0 || len(s.ParamFieldFrees) > 0 || len(s.GlobalFrees) > 0 || len(s.ReturnStores) > 0 {
			summaries[f.Name] = s
		}

		tree.Close()
	}

	return summaries
}

func findReturnStores(root parser.Node, f *db.Function) []string {
	var stores []string
	seen := make(map[string]bool)

	hasReturn := false
	for _, ret := range root.FindAll("return_statement") {
		if ret.StartLine() >= f.StartLine && ret.StartLine() <= f.EndLine {
			hasReturn = true
			break
		}
	}
	if !hasReturn {
		return nil
	}

	for _, assign := range root.FindAll("assignment_expression") {
		if assign.StartLine() < f.StartLine || assign.StartLine() > f.EndLine {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		lhs := children[0]
		globalName := extractGlobalFromArrayAccess(lhs)
		if globalName != "" && !seen[globalName] {
			seen[globalName] = true
			stores = append(stores, globalName)
		}
	}

	return stores
}

func extractFieldAccess(node parser.Node) (string, string) {
	children := node.NamedChildren()
	if len(children) >= 2 {
		baseVar := ""
		fieldName := ""
		if children[0].Kind() == "identifier" {
			baseVar = children[0].Text()
		}
		if children[1].Kind() == "field_identifier" {
			fieldName = children[1].Text()
		}
		return baseVar, fieldName
	}
	return "", ""
}

func extractGlobalFromArrayAccess(node parser.Node) string {
	if node.Kind() == "subscript_expression" {
		children := node.NamedChildren()
		if len(children) >= 1 && children[0].Kind() == "identifier" {
			name := children[0].Text()
			if strings.HasPrefix(name, "g_") {
				return name
			}
		}
	}
	if node.Kind() == "field_expression" {
		children := node.NamedChildren()
		if len(children) >= 1 {
			return extractGlobalFromArrayAccess(children[0])
		}
	}
	return ""
}

func getCallArgs(call parser.Node) []parser.Node {
	for _, child := range call.NamedChildren() {
		if child.Kind() == "argument_list" {
			return child.NamedChildren()
		}
	}
	return nil
}

func extractFunctionParams(root parser.Node, startLine int) []string {
	for _, fnNode := range root.FindAll("function_definition") {
		if fnNode.StartLine() != startLine {
			continue
		}
		for _, child := range fnNode.NamedChildren() {
			if child.Kind() == "function_declarator" {
				return extractParamsFromDeclarator(child)
			}
			if child.Kind() == "pointer_declarator" {
				for _, gc := range child.NamedChildren() {
					if gc.Kind() == "function_declarator" {
						return extractParamsFromDeclarator(gc)
					}
				}
			}
		}
	}
	return nil
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

type aliasInfo struct {
	baseVar  string
	field    string
}

func findAliases(f *db.Function, root parser.Node) map[string]aliasInfo {
	aliases := make(map[string]aliasInfo)

	for _, decl := range root.FindAll("init_declarator") {
		if decl.StartLine() < f.StartLine || decl.StartLine() > f.EndLine {
			continue
		}
		children := decl.NamedChildren()
		if len(children) < 2 {
			continue
		}
		lhs := children[0]
		rhs := children[1]

		aliasVar := extractVarFromDeclarator(lhs)
		if aliasVar == "" {
			continue
		}

		if rhs.Kind() == "identifier" {
			aliases[aliasVar] = aliasInfo{baseVar: rhs.Text(), field: ""}
		}

		if rhs.Kind() == "field_expression" {
			baseVar, fieldName := extractFieldAccess(rhs)
			if baseVar != "" {
				aliases[aliasVar] = aliasInfo{baseVar: baseVar, field: fieldName}
			}
		}
	}

	return aliases
}

func extractVarFromDeclarator(node parser.Node) string {
	if node.Kind() == "identifier" {
		return node.Text()
	}
	for _, child := range node.NamedChildren() {
		if v := extractVarFromDeclarator(child); v != "" {
			return v
		}
	}
	return ""
}

func (m summaryMap) hasSummary(name string) bool {
	_, ok := m[name]
	return ok
}