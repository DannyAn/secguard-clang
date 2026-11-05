package planner

import (
	"fmt"
	"strconv"
)

// externalIndexShapeKey is the shape key for the unchecked-external-index class
// (`array_oob_read_unchecked` / `array_oob_write_unchecked`): a fixed-size array
// indexed by a struct field with no in-code bounds check. The field's real range
// is the ONE judgment — if an external model (YANG leaf range, CLI value table,
// bounded nesting template) guarantees it, every access using that field against
// a capacity it fits is the same "pending external constraint" disposition; if
// nothing guarantees it, every access is the same out-of-bounds defect. Grouping
// by (file, index-source field, array capacity, access flavor, suspicion tier)
// folds that family into one AI review with the sites still listed.
//
// A machine-confirmed OOB is never folded: its certainty must stay its own row,
// and folding a suspected site under a confirmed representative would silently
// promote it.
func externalIndexShapeKey(c Candidate) string {
	if c.IndexSource == "" || c.SuspicionLevel == "confirmed" {
		return ""
	}
	capacity := c.CapacitySymbol
	if capacity == "" && c.Size > 0 {
		capacity = strconv.Itoa(c.Size)
	}
	return fmt.Sprintf("external-index-shape:%d:%s:%d:%s:%s:%s",
		c.FileID, c.IndexSource, c.Size, capacity, c.Category, c.SuspicionLevel)
}
