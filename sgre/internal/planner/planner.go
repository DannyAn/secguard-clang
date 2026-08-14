package planner

import (
	"context"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
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
			NewTypeExprFilter(),
			NewNonNullableFilter(),
			NewArrayOOBPrecedenceFilter(p.store),
			NewNullableSourceFilter(p.store),
			NewCallReachFilter(p.store),
			NewGuardFilter(p.store),
			NewSafeFunctionFilter(p.store),
		}
	case "memory-leak":
		return []Filter{
			NewCallReachFilter(p.store),
			NewSafeFunctionFilter(p.store),
			NewReleaseFilter(p.store, "MEMORY_RELEASE"),
		}
	case "resource-leak":
		return []Filter{
			NewCallReachFilter(p.store),
			NewSafeFunctionFilter(p.store),
			NewReleaseFilter(p.store, "RESOURCE_RELEASE"),
		}
	case "lifetime":
		return []Filter{
			NewCallReachFilter(p.store),
			NewSafeFunctionFilter(p.store),
			NewLifetimeFilter(p.store, p.parser, p.logger),
		}
	default:
		// Bounds-check suppression already happens in the buffer-overflow
		// detector (hasPrecedingBoundsCheck / constant-index analysis); there is
		// no bounds-check *event* for a filter to read, and the previous
		// BoundsCheckFilter wrongly keyed on NULL_GUARD events at function
		// granularity. So the default chain is call-reach + safe-function only.
		return []Filter{
			NewCallReachFilter(p.store),
			NewSafeFunctionFilter(p.store),
		}
	}
}

func (p *Planner) Plan(ctx context.Context, vulnType string) (*PlanResult, error) {
	spec, err := GetVulnTypeSpec(vulnType)
	if err != nil {
		return nil, err
	}

	seed, err := p.seedCandidatesByType(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("planner: seed: %w", err)
	}

	summary := PipelineSummary{
		SeedCount: len(seed),
	}

	filters := p.getFilters(spec.FilterChain)

	candidates := seed
	shortCircuited := false
	var dismissed []Dismissed
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

		filtered, dropped, err := filter.Apply(ctx, candidates)
		if err != nil {
			if p.logger != nil {
				p.logger.Warn("filter failed", "filter", filter.Name(), "error", err)
			}
			filtered = candidates
			dropped = nil
		} else {
			dismissed = append(dismissed, dropped...)
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
	summary.Dropped = dismissed
	if len(dismissed) > 0 {
		summary.DroppedByReason = make(map[string]int)
		for _, d := range dismissed {
			summary.DroppedByReason[d.Filter]++
		}
	}

	candidates = deduplicateCandidates(candidates, spec)

	result := &PlanResult{
		VulnerabilityType: vulnType,
		Candidates:        make([]EvidenceItem, 0),
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

func (p *Planner) seedCandidatesByType(ctx context.Context, spec *VulnTypeSpec) ([]Candidate, error) {
	events, err := p.store.ListEventsByType(ctx, spec.SeedEventType)
	if err != nil {
		return nil, fmt.Errorf("seed candidates: %w", err)
	}

	var candidates []Candidate
	for _, e := range events {
		props := parseEventProps(e.Properties)

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

		// The variable is the primary identity for dedup and variable-level
		// analysis. Fall back to the expression only for display/dedup of
		// types that carry no variable (e.g. integer-overflow, format-string).
		if len(spec.Categories) > 0 && !containsString(spec.Categories, props.Category) {
			continue
		}

		varName := props.Variable
		if varName == "" {
			varName = props.Expression
		}

		// The API name is the called function (or the registry API for the
		// RegSetValueEx branch), kept distinct from the variable so that
		// SafeFunctionFilter can do exact lookups rather than substring
		// matching against expression text.
		apiName := props.Function
		if apiName == "" {
			apiName = props.API
		}

		candidates = append(candidates, Candidate{
			DerefEventID: e.ID,
			FunctionID:   e.EntityID,
			FunctionName: funcName,
			VariableName: varName,
			APIName:      apiName,
			Category:     props.Category,
			LocationID:   e.LocationID,
			FileID:       fileID,
			Line:         line,
			NonNullable:  props.NonNullable == "true",
			IsTypeExpr:   props.IsTypeExpr == "true",
		})
	}

	return candidates, nil
}

func deduplicateCandidates(candidates []Candidate, spec *VulnTypeSpec) []Candidate {
	seen := make(map[string]int)
	result := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		key := spec.dedupKey(c)
		if idx, ok := seen[key]; ok {
			// Keep the earliest line for the same root cause so merged findings
			// anchor at the source (e.g. sprintf) rather than the sink
			// (sqlite3_exec) when both events collapse into one.
			if c.Line < result[idx].Line {
				result[idx] = c
			}
			continue
		}
		seen[key] = len(result)
		result = append(result, c)
	}
	return result
}

func (spec *VulnTypeSpec) dedupKey(c Candidate) string {
	if spec.ConvergeKey != nil {
		return spec.ConvergeKey(c)
	}
	if spec.ConvergeByVariable {
		// One finding per (function, variable): a single nullable variable
		// dereferenced at many sites is one defect, not many.
		return fmt.Sprintf("%d:%s:%s", c.FileID, c.FunctionName, c.VariableName)
	}
	return fmt.Sprintf("%d:%d:%s:%s", c.FileID, c.Line, c.FunctionName, c.VariableName)
}
