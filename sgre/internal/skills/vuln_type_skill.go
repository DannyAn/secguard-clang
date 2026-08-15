package skills

import (
	"context"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

type DomainAware interface {
	Domain() string
	Capabilities() []string
}

type VulnTypeSkill struct {
	name        string
	domain      string
	description string
	planner     *planner.Planner
}

func NewVulnTypeSkill(name, domain, description string, store db.Store, logger *log.Logger) *VulnTypeSkill {
	return &VulnTypeSkill{
		name:        name,
		domain:      domain,
		description: description,
		planner:     planner.NewPlanner(store, nil, logger),
	}
}

func (s *VulnTypeSkill) Name() string { return s.name }

func (s *VulnTypeSkill) Description() string { return s.description }

func (s *VulnTypeSkill) Domain() string { return s.domain }

func (s *VulnTypeSkill) Query(ctx context.Context) (*QueryResult, error) {
	result, err := s.planner.Plan(ctx, s.name)
	if err != nil {
		return nil, fmt.Errorf("%s skill: %w", s.name, err)
	}
	data, err := result.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("%s skill: json: %w", s.name, err)
	}
	return &QueryResult{Data: data}, nil
}

type skillSpec struct {
	name        string
	domain      string
	description string
}

var allSkillSpecs = []skillSpec{
	{"null-deref", "memory", "Detects null pointer dereferences using the convergence pipeline"},
	{"buffer-overflow", "boundary", "Detects buffer overflows (stack, heap, OOB write/read)"},
	{"memory-leak", "memory", "Detects memory leaks (path-sensitive, ownership-aware)"},
	{"injection", "input", "Detects command/SQL injection via taint flow to dangerous sinks"},
	{"resource-leak", "resource", "Detects resource leaks (file handles, sockets, locks)"},
	{"uninit", "initialization", "Detects use of uninitialized variables (path-aware)"},
	{"use-after-free", "memory", "Detects use-after-free via lifetime analysis"},
	{"double-free", "memory", "Detects double-free via free event tracking"},
	{"format-string", "input", "Detects format string vulnerabilities (printf with non-literal format)"},
	{"integer-overflow", "boundary", "Detects integer overflow in size calculations feeding malloc/memcpy"},
	{"race-condition", "concurrency", "Detects TOCTOU (filesystem and shared-state)"},
	{"hardcoded-secret", "trust", "Detects hardcoded passwords, API keys, tokens in source code"},
	{"deadlock", "concurrency", "Detects lock-order inversion via lock graph cycle detection"},
	{"crypto-misuse", "crypto", "Detects weak crypto algorithms, undersized keys, weak PRNG"},
	{"out-of-bounds", "boundary", "Detects out-of-bounds access (array and heap reads, CWE-125)"},
	{"divide-by-zero", "boundary", "Detects division/modulo by a possibly-zero divisor (CWE-369)"},
	{"unchecked-return", "boundary", "Detects unchecked malloc/fopen/read return values (CWE-252)"},
	{"path-traversal", "input", "Detects non-literal paths into filesystem sinks (CWE-22)"},
	{"sizeof-misuse", "boundary", "Detects sizeof on pointer variables in size contexts (CWE-467/468)"},
	{"signed-compare", "boundary", "Detects unsigned values compared with zero/negative (CWE-681/195)"},
}

func DefaultRegistry(store db.Store, logger *log.Logger) *Registry {
	reg := NewRegistry()
	for _, spec := range allSkillSpecs {
		reg.Register(NewVulnTypeSkill(spec.name, spec.domain, spec.description, store, logger))
	}
	return reg
}

func AllDomains() []string {
	seen := make(map[string]bool)
	for _, spec := range allSkillSpecs {
		seen[spec.domain] = true
	}
	result := make([]string, 0, len(seen))
	for d := range seen {
		result = append(result, d)
	}
	return result
}

func SkillsByDomain(domain string) []string {
	var result []string
	for _, spec := range allSkillSpecs {
		if spec.domain == domain {
			result = append(result, spec.name)
		}
	}
	return result
}
