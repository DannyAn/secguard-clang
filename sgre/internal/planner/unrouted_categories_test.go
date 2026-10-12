package planner

import "testing"

// TestUnroutedCategories pins the seed-stage category-routing audit fix. Several
// vuln types share one seed event, so out-of-bounds legitimately drops the
// write-flavored BUFFER_ACCESS categories that buffer-overflow owns — the old
// warning logged spec.Categories (the type's own allow-list) and read as "the
// allowed categories were dropped", which produced a phantom OOB false-negative
// alarm in a real scan. Only a category claimed by NO type is a real drift.
func TestUnroutedCategories(t *testing.T) {
	p := NewPlanner(nil, nil, nil)
	oob, err := GetVulnTypeSpec("out-of-bounds")
	if err != nil {
		t.Fatalf("out-of-bounds spec: %v", err)
	}

	// Write-flavored categories are claimed by buffer-overflow: routed, not lost.
	routed := p.unroutedCategories(oob, map[string]int{"array_oob_write": 3, "heap_oob_write": 3})
	if len(routed) != 0 {
		t.Errorf("write-flavored categories are routed to buffer-overflow, want no orphans, got %v", routed)
	}

	// A category no registered type claims is the real drift and must surface.
	orphan := p.unroutedCategories(oob, map[string]int{"array_oob_write": 3, "brand_new_category": 2})
	if orphan["brand_new_category"] != 2 {
		t.Errorf("unclaimed category must be reported as an orphan with its count, got %v", orphan)
	}
	if _, ok := orphan["array_oob_write"]; ok {
		t.Errorf("claimed category must not be reported as an orphan, got %v", orphan)
	}
}
