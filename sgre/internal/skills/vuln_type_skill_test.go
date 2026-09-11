package skills

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/planner"
)

// TestVulnTypeSkillConsistency is the extensibility guard: the type list lives in
// exactly one place (planner/registry.go), and this test fails the build when
// any of the three parallel views drift —
//
//  1. every RegisterVulnType has a SKILL.md, and every SKILL.md has a registered
//     type (a type without a skill means the AI classifies with no type-specific
//     rules; a skill without a type is an orphan that never loads — the v0.5.x
//     uninit/resource-leak failure mode);
//  2. the CLI skill registry (allSkillSpecs) matches the planner registry, so
//     `secguard types` never disagrees with the agent skills.
//
// Adding a detection therefore means touching the same three places the
// NEW_SKILL.md checklist enumerates; forgetting one fails here.
func TestVulnTypeSkillConsistency(t *testing.T) {
	types := planner.AllVulnTypes()
	typeSet := make(map[string]bool, len(types))
	for _, n := range types {
		typeSet[n] = true
	}

	// 1. skill dirs == registered types (1:1).
	skillsDir := filepath.Join("..", "..", "..", "extension", "shared", "skills")
	entries, err := os.ReadDir(skillsDir)
	if err != nil {
		t.Fatalf("read skills dir: %v", err)
	}
	skillSet := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(skillsDir, e.Name(), "SKILL.md")); err == nil {
			skillSet[e.Name()] = true
		}
	}

	for n := range typeSet {
		if !skillSet[n] {
			t.Errorf("vuln type %q has no extension/shared/skills/%s/SKILL.md (add the skill per NEW_SKILL.md)", n, n)
		}
	}
	for n := range skillSet {
		if !typeSet[n] {
			t.Errorf("skill dir %q has no RegisterVulnType entry (it would never load)", n)
		}
	}

	// 2. the CLI skill registry matches the planner registry.
	regNames := make([]string, 0, len(allSkillSpecs))
	for _, s := range allSkillSpecs {
		regNames = append(regNames, s.name)
	}
	sort.Strings(regNames)
	if !equalStrings(regNames, types) {
		t.Errorf("allSkillSpecs (%d) != planner.AllVulnTypes() (%d)\n  registry: %v\n  planner:  %v",
			len(regNames), len(types), regNames, types)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
