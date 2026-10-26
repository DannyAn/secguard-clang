package skills

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/planner"
)

var (
	fragmentTypeRe = regexp.MustCompile(`Type:\s+"([a-z_]+)"`)
	specNameRe     = regexp.MustCompile(`Name:\s+"([a-z-]+)",`)
	boldBulletRe   = regexp.MustCompile(`\*\*([^*]+)\*\*`)
)

// exemptBold lists Evidence Pattern bullets that name the seed EVENT or a
// concept, not an evidence-file fragment; they have no `Type: "<name>"`
// counterpart in BuildEvidence by design. confirmed/dismissed/possible are
// the detector-category table's pre-verdict words — fragments are always
// snake_case, so these can never collide with a real fragment name.
var exemptBold = map[string]bool{
	"BUFFER_ACCESS event": true, "DEADLOCK event": true, "INJECTION event": true,
	"CRYPTO_MISUSE event": true, "RACE_CONDITION event": true, "ARITH_OVERFLOW event": true,
	"HARDCODED_SECRET event": true,
	"No bounds check":        true, "Reachable": true, "Sink context": true,
	"No overflow check": true, "Unsigned subtraction": true,
	"confirmed": true, "dismissed": true, "possible": true,
}

// sharedFragments are appended outside the type's BuildEvidence (in
// newEvidenceItem), so no registry block contains them.
var sharedFragments = map[string]bool{
	"weak_guard": true,
	// flow_step is emitted by the shared bufferFlowSteps helper (called from the
	// buffer-overflow AND out-of-bounds BuildEvidence blocks), so its `Type:`
	// literal lives in a top-level function, not in either registry block.
	"flow_step": true,
}

// TestSkillFragmentsMatchBuildEvidence guards the evidence contract between
// each SKILL.md's Evidence Pattern section and the registry's BuildEvidence
// implementation. E-02/E-03 drifted exactly this way: the implementation
// learned a new fragment (buffer/index, callee_definition) while the skill
// kept describing the old shape, so the AI read the skill expecting one
// evidence file and found another. Both directions are checked:
//
//  1. every fragment the SKILL promises (a `- **<name>**` bullet inside the
//     Evidence Pattern section) is a `Type: "<name>"` literal in that type's
//     RegisterVulnType block (or in sharedFragments);
//  2. every `Type: "<name>"` literal the block emits is promised by the SKILL
//     (or in sharedFragments).
func TestSkillFragmentsMatchBuildEvidence(t *testing.T) {
	impl := registryFragmentSets(t)
	for _, typeName := range planner.AllVulnTypes() {
		implSet := impl[typeName]
		if implSet == nil {
			t.Errorf("type %q: no RegisterVulnType block found in registry.go", typeName)
			continue
		}
		promised := skillPromisedFragments(t, typeName)
		var missing []string
		for frag := range promised {
			if !implSet[frag] && !sharedFragments[frag] {
				missing = append(missing, frag)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			t.Errorf("type %q: SKILL promises fragments the implementation never emits %v (update the SKILL's Evidence Pattern or the BuildEvidence)", typeName, missing)
		}
		var undocumented []string
		for frag := range implSet {
			if !promised[frag] {
				undocumented = append(undocumented, frag)
			}
		}
		if len(undocumented) > 0 {
			sort.Strings(undocumented)
			t.Errorf("type %q: BuildEvidence emits fragments the SKILL never promises %v (add them to the SKILL's Evidence Pattern)", typeName, undocumented)
		}
	}
}

// registryFragmentSets splits registry.go AND its per-type companions
// (registry_<type>.go, introduced by the Phase-8 registry split) into
// per-spec blocks keyed by the `Name: "<type>"` literal and collects every
// `Type: "<fragment>"` literal in the block — the fragment vocabulary that
// spec's BuildEvidence can emit.
func registryFragmentSets(t *testing.T) map[string]map[string]bool {
	paths := []string{filepath.Join("..", "planner", "registry.go")}
	matches, err := filepath.Glob(filepath.Join("..", "planner", "registry_*.go"))
	if err != nil {
		t.Fatalf("glob registry_*.go: %v", err)
	}
	paths = append(paths, matches...)
	sets := map[string]map[string]bool{}
	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		current := ""
		for _, line := range strings.Split(string(src), "\n") {
			if m := specNameRe.FindStringSubmatch(line); m != nil {
				current = m[1]
				if sets[current] == nil {
					sets[current] = map[string]bool{}
				}
				continue
			}
			if current == "" {
				continue
			}
			if m := fragmentTypeRe.FindStringSubmatch(line); m != nil {
				sets[current][m[1]] = true
			}
		}
	}
	return sets
}

// skillPromisedFragments extracts the `- **<name>**` bullets from a SKILL.md's
// Evidence Pattern section (up to the next `### ` heading).
func skillPromisedFragments(t *testing.T, typeName string) map[string]bool {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "extension", "shared", "skills", typeName, "SKILL.md"))
	if err != nil {
		t.Fatalf("read SKILL.md for %s: %v", typeName, err)
	}
	promised := map[string]bool{}
	inSection := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "### ") {
			inSection = strings.HasPrefix(line, "### Evidence Pattern")
			continue
		}
		if !inSection || !strings.HasPrefix(line, "- ") {
			continue
		}
		for _, m := range boldBulletRe.FindAllStringSubmatch(line, -1) {
			name := m[1]
			if exemptBold[name] {
				continue
			}
			promised[name] = true
		}
	}
	return promised
}
