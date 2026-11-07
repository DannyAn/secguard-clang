package skills

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
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
// ADDING_A_VULN_TYPE.md checklist enumerates; forgetting one fails here.
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
			t.Errorf("vuln type %q has no extension/shared/skills/%s/SKILL.md (add the skill per ADDING_A_VULN_TYPE.md)", n, n)
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

	// 3. SKILL frontmatter severity == registry DefaultSeverity (lowercased).
	// The scale is single-sourced in the registry (GAP-10); the frontmatter
	// `metadata.severity` is the derived mirror and must not drift.
	for name := range typeSet {
		spec, err := planner.GetVulnTypeSpec(name)
		if err != nil || spec.DefaultSeverity == "" {
			continue
		}
		fm := skillFrontmatterSeverity(t, name)
		if fm != "" && strings.ToLower(fm) != spec.DefaultSeverity {
			t.Errorf("type %q: SKILL frontmatter severity %q != registry DefaultSeverity %q", name, fm, spec.DefaultSeverity)
		}
	}
}

// skillFrontmatterSeverity returns the SKILL.md frontmatter `severity:` value
// (raw spelling), or "" when the skill has no such field.
func skillFrontmatterSeverity(t *testing.T, typeName string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "extension", "shared", "skills", typeName, "SKILL.md"))
	if err != nil {
		t.Fatalf("read SKILL.md for %s: %v", typeName, err)
	}
	text := string(data)
	// The frontmatter is the block between the first two `---` fences.
	parts := strings.SplitN(text, "---", 3)
	if len(parts) < 3 {
		return ""
	}
	for _, line := range strings.Split(parts[1], "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "severity:") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "severity:"))
		}
	}
	return ""
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

// TestSeedEventTypesInSchema guards the event-type vocabulary contract: every
// seed/aux event type the registry can emit must be writable to
// security_events. The storage layer deliberately has NO CHECK enum (the
// registry owns the vocabulary, not the DB), so this verifies the table and
// column exist and the CHECK has not been reintroduced — while the registry's
// AllSeedEventTypes/AuxEvidenceEventTypes remain the single source of truth.
func TestSeedEventTypesInSchema(t *testing.T) {
	ddl := db.SchemaDDL
	start := strings.Index(ddl, "CREATE TABLE IF NOT EXISTS security_events")
	if start < 0 {
		t.Fatal("SchemaDDL must contain security_events")
	}
	seg := ddl[start:]
	if end := strings.Index(seg, ");"); end >= 0 {
		seg = seg[:end]
	}
	if strings.Contains(seg, "CHECK (") || strings.Contains(seg, "CHECK(") {
		t.Errorf("security_events.event_type must not carry a CHECK enum; the registry owns the vocabulary: %s", seg)
	}
	if !strings.Contains(seg, "event_type") {
		t.Errorf("security_events must have an event_type column: %s", seg)
	}
}
