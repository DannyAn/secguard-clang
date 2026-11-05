// Package build consumes compile_commands.json (GAP-03, C1 tier): the global
// union of -D numeric macros and -I include directories across every
// translation unit, merged into the whole-tree index (the per-TU precise
// environment is the deferred C2 tier).
package build

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// CompileCommands is the extracted global-union view of a compile_commands.json:
// numeric -D defines (name -> value) and -I include directories.
// TUs holds per-translation-unit configs for Type Layout (GAP-1038 Phase 1a).
type CompileCommands struct {
	Defines     map[string]int
	IncludeDirs []string
	TUs         []TUConfig
	Path        string
}

// LoadCompileCommands parses a compile_commands.json file. It accepts both the
// `arguments` array and the `command` string forms, and extracts -DNAME / -D NAME
// / -DNAME=VAL and -Idir / -I dir; everything else is ignored. Only NUMERIC -D
// defines are kept (function-like / non-numeric macros are skipped with a
// warning-free drop — they are resolved from source #defines instead).
func LoadCompileCommands(path string) (*CompileCommands, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read compile_commands: %w", err)
	}
	var entries []struct {
		File      string   `json:"file"`
		Directory string   `json:"directory"`
		Arguments []string `json:"arguments"`
		Command   string   `json:"command"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse compile_commands: %w", err)
	}

	cc := &CompileCommands{
		Defines:     map[string]int{},
		IncludeDirs: []string{},
		Path:        path,
	}
	seenDef := map[string]int{}
	seenInc := map[string]bool{}

	handleToken := func(tok string, next func() string) {
		switch {
		case tok == "-D":
			if v := next(); v != "" {
				applyDefine(cc, seenDef, v)
			}
		case strings.HasPrefix(tok, "-D") && len(tok) > 2:
			applyDefine(cc, seenDef, tok[2:])
		case tok == "-I":
			if v := next(); v != "" {
				addInclude(cc, seenInc, v)
			}
		case strings.HasPrefix(tok, "-I") && len(tok) > 2:
			addInclude(cc, seenInc, tok[2:])
		}
	}

	for _, e := range entries {
		if len(e.Arguments) > 0 {
			args := e.Arguments
			for i := 0; i < len(args); i++ {
				handleToken(args[i], func() string {
					if i+1 < len(args) {
						return args[i+1]
					}
					return ""
				})
			}
			cc.TUs = append(cc.TUs, parseTUConfig(e.File, e.Directory, args))
			continue
		}
		// shell-rough-tokenize the command string (no new dependency).
		toks := strings.Fields(e.Command)
		for i := 0; i < len(toks); i++ {
			handleToken(toks[i], func() string {
				if i+1 < len(toks) {
					return toks[i+1]
				}
				return ""
			})
		}
		cc.TUs = append(cc.TUs, parseTUConfig(e.File, e.Directory, toks))
	}
	return cc, nil
}

func applyDefine(cc *CompileCommands, seen map[string]int, def string) {
	name, val, ok := splitDefine(def)
	if !ok {
		return
	}
	if _, dup := seen[name]; !dup {
		seen[name] = val
	}
	cc.Defines[name] = val
}

func splitDefine(def string) (name string, val int, ok bool) {
	name = def
	val = 1
	if i := strings.IndexByte(def, '='); i >= 0 {
		name = def[:i]
		v, err := strconv.Atoi(strings.TrimSpace(def[i+1:]))
		if err != nil {
			return "", 0, false // non-numeric macro → dropped
		}
		val = v
	}
	if name == "" {
		return "", 0, false
	}
	return name, val, true
}

func addInclude(cc *CompileCommands, seen map[string]bool, dir string) {
	if dir == "" || seen[dir] {
		return
	}
	seen[dir] = true
	cc.IncludeDirs = append(cc.IncludeDirs, dir)
}

// currentCompileCommands is the process-wide resolved compile_commands (set by
// the CLI at startup; read by the constant-environment builder). Nil = no
// compile_commands (zero-config behavior unchanged).
var currentCompileCommands *CompileCommands

// SetCompileCommands stores the resolved compile_commands for the current run.
func SetCompileCommands(cc *CompileCommands) { currentCompileCommands = cc }

// CurrentCompileCommands returns the resolved compile_commands, or nil.
func CurrentCompileCommands() *CompileCommands { return currentCompileCommands }
