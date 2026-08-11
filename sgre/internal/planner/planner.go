package planner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kongan/secguard-lite/internal/db"
	"github.com/kongan/secguard-lite/internal/log"
	"github.com/kongan/secguard-lite/internal/parser"
)

type Planner struct {
	store         db.Store
	parser        *parser.Parser
	logger        *log.Logger
	MaxCandidates int
}

func NewPlanner(store db.Store, p *parser.Parser, logger *log.Logger) *Planner {
	return &Planner{store: store, parser: p, logger: logger, MaxCandidates: 30}
}

func (p *Planner) SetMaxCandidates(n int) {
	if n > 0 {
		p.MaxCandidates = n
	}
}

func (p *Planner) getFilters(chain string) []Filter {
	switch chain {
	case "null-deref":
		return []Filter{
			NewNonNullableFilter(),
			NewArrayOOBPrecedenceFilter(p.store),
			NewNullableSourceFilter(p.store),
			NewCallReachFilter(p.store),
			NewGuardFilter(p.store),
			NewSafeFunctionFilter(p.store),
			NewBoundsCheckFilter(p.store),
		}
	case "memory-leak":
		return []Filter{
			NewCallReachFilter(p.store),
			NewSafeFunctionFilter(p.store),
			NewMemoryReleaseFilter(p.store),
		}
	case "resource-leak":
		return []Filter{
			NewCallReachFilter(p.store),
			NewSafeFunctionFilter(p.store),
			NewResourceReleaseFilter(p.store),
		}
	case "lifetime":
		return []Filter{
			NewCallReachFilter(p.store),
			NewSafeFunctionFilter(p.store),
			NewLifetimeFilter(p.store, p.parser, p.logger),
		}
	default:
		return []Filter{
			NewCallReachFilter(p.store),
			NewSafeFunctionFilter(p.store),
			NewBoundsCheckFilter(p.store),
		}
	}
}

func (p *Planner) Plan(ctx context.Context, vulnType string) (*PlanResult, error) {
	spec, err := GetVulnTypeSpec(vulnType)
	if err != nil {
		return nil, err
	}

	seed, err := p.seedCandidatesByType(ctx, spec.SeedEventType)
	if err != nil {
		return nil, fmt.Errorf("planner: seed: %w", err)
	}

	summary := PipelineSummary{
		SeedCount: len(seed),
	}

	filters := p.getFilters(spec.FilterChain)

	candidates := seed
	shortCircuited := false
	for _, filter := range filters {
		inputCount := len(candidates)
		if inputCount == 0 {
			shortCircuited = true
			summary.Filters = append(summary.Filters, FilterStats{
				Name:        filter.Name(),
				InputCount:  0,
				OutputCount: 0,
			})
			break
		}

		filtered, err := filter.Apply(ctx, candidates)
		if err != nil {
			if p.logger != nil {
				p.logger.Warn("filter failed", "filter", filter.Name(), "error", err)
			}
			filtered = candidates
		}

		outputCount := len(filtered)
		summary.Filters = append(summary.Filters, FilterStats{
			Name:        filter.Name(),
			InputCount:  inputCount,
			OutputCount: outputCount,
		})

		if p.logger != nil {
			p.logger.Info("filter applied", "filter", filter.Name(), "input", inputCount, "output", outputCount)
		}

		candidates = filtered
	}

	summary.ShortCircuited = shortCircuited
	summary.FinalCount = len(candidates)

	candidates = deduplicateCandidates(candidates)

	result := &PlanResult{
		VulnerabilityType: vulnType,
		Summary:           summary,
	}

	maxCand := p.MaxCandidates
	if maxCand <= 0 {
		maxCand = 30
	}
	candidates = RankCandidates(ctx, candidates, p.store)
	if len(candidates) > maxCand {
		candidates = candidates[:maxCand]
	}

	for _, c := range candidates {
		fileName := ""
		if c.FileID > 0 {
			if file, err := p.store.GetFileByID(ctx, c.FileID); err == nil && file != nil {
				fileName = file.Path
			}
		}
		result.Candidates = append(result.Candidates, newEvidenceItem(c, spec, fileName))
	}

	return result, nil
}

func (p *Planner) seedCandidatesByType(ctx context.Context, eventType string) ([]Candidate, error) {
	events, err := p.store.ListEventsByType(ctx, eventType)
	if err != nil {
		return nil, fmt.Errorf("seed candidates: %w", err)
	}

	var candidates []Candidate
	for _, e := range events {
		var props struct {
			Variable    string `json:"variable"`
			Expression  string `json:"expression"`
			Function    string `json:"function"`
			Category    string `json:"category"`
			NonNullable string `json:"non_nullable"`
		}
		json.Unmarshal([]byte(e.Properties), &props)

		fn, _ := p.store.GetFunctionByID(ctx, e.EntityID)
		funcName := ""
		fileID := int64(0)
		if fn != nil {
			funcName = fn.Name
			fileID = fn.FileID
		}

		line := 0
		if e.LocationID > 0 {
			loc, _ := p.store.GetLocationByID(ctx, e.LocationID)
			if loc != nil {
				line = loc.Line
			}
		}

		varName := props.Variable
		if varName == "" {
			varName = props.Expression
		}

		candidates = append(candidates, Candidate{
			DerefEventID: e.ID,
			FunctionID:   e.EntityID,
			FunctionName: funcName,
			VariableName: varName,
			LocationID:   e.LocationID,
			FileID:       fileID,
			Line:         line,
			NonNullable:  props.NonNullable == "true",
		})
	}

	return candidates, nil
}

func deduplicateCandidates(candidates []Candidate) []Candidate {
	seen := make(map[string]bool)
	result := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		key := fmt.Sprintf("%d:%d:%s:%s", c.FileID, c.Line, c.FunctionName, c.VariableName)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, c)
	}
	return result
}
