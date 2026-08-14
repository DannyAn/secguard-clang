package evidence

import (
	"testing"
)

// TestUninit_SizeofPseudoDerefNotHeapUninit guards the symmetric case in the
// uninit detector: sizeof(node->field) / sizeof(node[0]) are unevaluated type
// expressions, not reads of the (uninitialized) heap memory node points at, so
// detectHeapUninit must not flag them as heap_uninit.
func TestUninit_SizeofPseudoDerefNotHeapUninit(t *testing.T) {
	store := runIndexAndDetect(t, "tc41_sizeof_pseudo_deref.c")
	assertNoEvent(t, store, "VALUE_USE", "tc41_sizeof_pseudo_deref.c")
}
