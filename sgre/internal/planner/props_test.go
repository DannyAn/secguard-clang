package planner

import "testing"

// TestParseEventProps_FlexIntSize pins the two-shape size decode: detectors
// that emit properties via map[string]string write numbers as strconv.Itoa
// strings ("4"), while map[string]any emitters write JSON numbers. A plain int
// field silently zeroes on the string shape, which broke the OOB capacity
// chain (emitOOB size → Candidate.Size → range_oob filter / evidence render).
func TestParseEventProps_FlexIntSize(t *testing.T) {
	str := parseEventProps(`{"size":"4","array":"a","index":"9"}`)
	if int(str.Size) != 4 {
		t.Errorf(`string size "4" = %d, want 4`, str.Size)
	}
	if str.Array != "a" || str.Index != "9" {
		t.Errorf("string-shaped event should still decode sibling fields, got array=%q index=%q", str.Array, str.Index)
	}

	num := parseEventProps(`{"size":16}`)
	if int(num.Size) != 16 {
		t.Errorf(`number size 16 = %d, want 16`, num.Size)
	}

	absent := parseEventProps(`{"array":"a"}`)
	if absent.Size != 0 {
		t.Errorf("absent size = %d, want 0", absent.Size)
	}

	// A non-numeric size (e.g. crypto key_size carrying source text) must not
	// take the sibling fields down with it: the unmarshal error is swallowed
	// and every successfully decoded key survives.
	bad := parseEventProps(`{"key_size":"EVP_MAX_KEY_BITS","category":"weak_key","size":"8"}`)
	if bad.Category != "weak_key" || int(bad.Size) != 8 {
		t.Errorf("a bad sibling key must not lose the rest: category=%q size=%d", bad.Category, bad.Size)
	}
	if bad.KeySize != 0 {
		t.Errorf("non-numeric key_size = %d, want 0", bad.KeySize)
	}
}

// F2 regression: the race-condition detector emits thread_instances/write_line
// through a map[string]string, so they arrive as numeric STRINGS in the event
// JSON. Plain int fields silently zeroed on unmarshal, which dropped the
// instances@/write@ facts from every shared_data_race hint. flexInt must decode
// both the string shape and the numeric (map[string]any) shape.
func TestParseEventProps_RaceCountersDecodeFromStringAndNumber(t *testing.T) {
	fromString := parseEventProps(`{"variable":"g_count","category":"shared_data_race","thread_functions":"t_a,t_b","thread_instances":"2","write_line":"40"}`)
	if fromString.ThreadInstances != 2 || fromString.WriteLine != 40 {
		t.Errorf("string-shaped race counters must decode: instances=%d write_line=%d", fromString.ThreadInstances, fromString.WriteLine)
	}
	if fromString.ThreadFunctions != "t_a,t_b" {
		t.Errorf("thread_functions = %q", fromString.ThreadFunctions)
	}

	fromNumber := parseEventProps(`{"variable":"g_count","thread_instances":3,"write_line":77}`)
	if fromNumber.ThreadInstances != 3 || fromNumber.WriteLine != 77 {
		t.Errorf("number-shaped race counters must decode: instances=%d write_line=%d", fromNumber.ThreadInstances, fromNumber.WriteLine)
	}

	garbage := parseEventProps(`{"thread_instances":"many","write_line":""}`)
	if garbage.ThreadInstances != 0 || garbage.WriteLine != 0 {
		t.Errorf("non-numeric values must decode to 0 without breaking sibling fields: %+v", garbage)
	}
}
