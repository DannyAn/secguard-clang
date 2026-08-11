package planner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type LifetimeFilter struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewLifetimeFilter(store db.Store, p *parser.Parser, logger *log.Logger) *LifetimeFilter {
	return &LifetimeFilter{store: store, parser: p, logger: logger}
}

func (f *LifetimeFilter) Name() string { return "lifetime" }

func (f *LifetimeFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, error) {
	var result []Candidate
	for _, c := range candidates {
		if f.isFalsePositive(ctx, c) {
			continue
		}
		result = append(result, c)
	}
	return result, nil
}

func (f *LifetimeFilter) isFalsePositive(ctx context.Context, c Candidate) bool {
	event, err := f.store.GetEventByID(ctx, c.DerefEventID)
	if err != nil || event == nil {
		return false
	}

	var props struct {
		FreeLine int    `json:"free_line"`
		UseLine  int    `json:"use_line"`
		Variable string `json:"variable"`
	}
	json.Unmarshal([]byte(event.Properties), &props)
	if props.FreeLine == 0 || props.UseLine == 0 {
		return false
	}

	fn, err := f.store.GetFunctionByID(ctx, c.FunctionID)
	if err != nil || fn == nil {
		return false
	}

	file, err := f.store.GetFileByID(ctx, fn.FileID)
	if err != nil || file == nil {
		return false
	}

	source, err := os.ReadFile(file.Path)
	if err != nil {
		return false
	}

	tree, err := f.parser.Parse(source, file.Path)
	if err != nil {
		return false
	}
	defer tree.Close()

	cfg := graph.BuildCFG(tree.RootNode(), fn.StartLine, fn.EndLine)
	if !cfg.CanReach(props.FreeLine, props.UseLine) {
		if f.logger != nil {
			f.logger.Info("lifetime filter: removed false positive",
				"variable", props.Variable,
				"free_line", props.FreeLine,
				"use_line", props.UseLine,
				"function", fn.Name,
			)
		}
		return true
	}

	return false
}

var _ = fmt.Sprintf
