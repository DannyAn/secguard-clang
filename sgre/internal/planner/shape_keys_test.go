package planner

import "testing"

// TestExternalIndexShapeKey pins Issue #216 item 3's shape identity: the
// unchecked-external-index family folds by (file, index-source field, capacity,
// access flavor, suspicion tier). Same-shape sites share a key, everything the
// external-bound judgment depends on splits it, and confirmed candidates /
// non-external-index candidates opt out of clustering.
func TestExternalIndexShapeKey(t *testing.T) {
	base := Candidate{
		FileID:         7,
		IndexSource:    "actived_index",
		Size:           4,
		CapacitySymbol: "SVR_CNT",
		Category:       "array_oob_read_unchecked",
		SuspicionLevel: "suspected",
	}
	baseKey := externalIndexShapeKey(base)
	if baseKey == "" {
		t.Fatal("base unchecked external-index candidate must produce a shape key")
	}

	// Function and line are NOT part of the shape: the whole point is one review
	// for the family across the file's functions.
	other := base
	other.FunctionName = "another_filling_function"
	other.Line = 99
	if got := externalIndexShapeKey(other); got != baseKey {
		t.Errorf("same shape in another function must share the key, got %q vs %q", got, baseKey)
	}

	cases := []struct {
		name   string
		mutate func(c *Candidate)
	}{
		{"different file", func(c *Candidate) { c.FileID = 8 }},
		{"different index source", func(c *Candidate) { c.IndexSource = "other_index" }},
		{"different size", func(c *Candidate) { c.Size = 2 }},
		{"different capacity symbol", func(c *Candidate) { c.CapacitySymbol = "OTHER_CNT" }},
		{"different access flavor", func(c *Candidate) { c.Category = "array_oob_write_unchecked" }},
		{"different suspicion tier", func(c *Candidate) { c.SuspicionLevel = "possible" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mutate(&c)
			if got := externalIndexShapeKey(c); got == baseKey {
				t.Errorf("%s must NOT share the base shape key, got %q", tc.name, got)
			}
		})
	}

	// A machine-confirmed OOB keeps its own row: folding a suspected site under
	// it would silently promote that site.
	confirmed := base
	confirmed.SuspicionLevel = "confirmed"
	if got := externalIndexShapeKey(confirmed); got != "" {
		t.Errorf("confirmed candidate must opt out of clustering, got %q", got)
	}
	// The shape key belongs to the unchecked external-index class only.
	noSource := base
	noSource.IndexSource = ""
	if got := externalIndexShapeKey(noSource); got != "" {
		t.Errorf("candidate without an index source must opt out, got %q", got)
	}

	// A literal capacity (no macro symbol) still identifies the shape.
	literal := base
	literal.CapacitySymbol = ""
	literal.Size = 3
	if got := externalIndexShapeKey(literal); got == "" || got == baseKey {
		t.Errorf("literal capacity must produce its own key, got %q (base %q)", got, baseKey)
	}
}
