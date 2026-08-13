package evidence

import (
	"testing"
)

func TestArrayOOB_LoopBoundOverflow(t *testing.T) {
	store := runIndexAndDetect(t, "tc22_off_by_one.c")
	assertHasEvent(t, store, "BUFFER_ACCESS", "LoopBoundOverflow")
}

func TestBufferOverflow_HeapOOBWrite(t *testing.T) {
	store := runIndexAndDetect(t, "tc35_heap_oob_write.c")
	assertEventCategory(t, store, "BUFFER_ACCESS", "heap_oob_write", "tc35_heap_oob_write")
}

func TestBufferOverflow_FormatOverflow(t *testing.T) {
	store := runIndexAndDetect(t, "tc36_format_overflow.c")
	assertEventCategory(t, store, "BUFFER_ACCESS", "format_overflow", "tc36_format_overflow")
}

func TestBufferOverflow_FormatOverflowSuppressedByInjectionSink(t *testing.T) {
	// sprintf feeding sqlite3_exec is one SQL-injection defect; the same call
	// must not also surface as a buffer-overflow candidate (double counting).
	store := runIndexAndDetect(t, "tc40_sprintf_sql_sink.c")
	assertNoEvent(t, store, "BUFFER_ACCESS", "tc40_sprintf_sql_sink")
	assertHasEvent(t, store, "INJECTION", "tc40_sprintf_sql_sink")
}
