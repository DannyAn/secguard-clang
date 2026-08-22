package evidence

import (
	"strings"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

// macroFreeSummary describes a function-like macro that frees (and optionally
// nulls) its first parameter: `#define SAFE_FREE(p) do { free(p); p = NULL; } while(0)`.
// tree-sitter exposes such macros as preproc_function_def nodes, whose body is a
// preproc_arg — the raw replacement text, analyzed here so a call to the macro
// can be treated as a free site.
type macroFreeSummary struct {
	freesArg bool
	nullsArg bool
}

// macroFreeSummaries returns, per macro name, whether its body frees the first
// parameter and whether it then nulls it. It is the macro layer the memory
// detectors consult so `#define my_free(p) free(p)` wrapping is not invisible.
func macroFreeSummaries(root parser.Node) map[string]macroFreeSummary {
	out := make(map[string]macroFreeSummary)
	for _, def := range root.FindAll("preproc_function_def") {
		name, param, body := "", "", ""
		for _, child := range def.NamedChildren() {
			switch child.Kind() {
			case "identifier":
				if name == "" {
					name = child.Text()
				}
			case "preproc_params":
				for _, p := range child.NamedChildren() {
					if p.Kind() == "identifier" && param == "" {
						param = p.Text()
					}
				}
			case "preproc_arg":
				body = child.Text()
			}
		}
		if name == "" || param == "" || body == "" {
			continue
		}
		s := macroFreeSummary{}
		if strings.Contains(body, "free("+param+")") || strings.Contains(body, "free ("+param+")") {
			s.freesArg = true
		}
		if s.freesArg && (strings.Contains(body, param+" = NULL") || strings.Contains(body, param+"=NULL") ||
			strings.Contains(body, param+" = 0")) {
			s.nullsArg = true
		}
		out[name] = s
	}
	return out
}
