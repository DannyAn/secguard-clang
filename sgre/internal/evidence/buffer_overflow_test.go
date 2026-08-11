package evidence

import (
	"testing"
)

func TestArrayOOB_LoopBoundOverflow(t *testing.T) {
	store := runIndexAndDetect(t, "tc22_off_by_one.c")
	assertHasEvent(t, store, "BUFFER_ACCESS", "LoopBoundOverflow")
}
