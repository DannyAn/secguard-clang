package planner

import (
	"reflect"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/config"
)

func TestAppendContractHints(t *testing.T) {
	contracts := map[string]config.Contract{
		"framework_send_data": {TakesOwnership: "param-1", Releases: "on-success"},
		"vendor_hton_buf":     {OutParams: []string{"param-4"}},
	}

	parts := appendContractHints(nil, Candidate{APIName: "framework_send_data"}, contracts)
	want := []string{"user-contract@framework_send_data", "takes-ownership@param-1", "release@on-success"}
	if !reflect.DeepEqual(parts, want) {
		t.Errorf("got %v, want %v", parts, want)
	}

	parts = appendContractHints(nil, Candidate{APIName: "vendor_hton_buf"}, contracts)
	want = []string{"user-contract@vendor_hton_buf", "outparam@param-4"}
	if !reflect.DeepEqual(parts, want) {
		t.Errorf("got %v, want %v", parts, want)
	}

	// No matching contract -> no tokens.
	if got := appendContractHints(nil, Candidate{APIName: "malloc"}, contracts); len(got) != 0 {
		t.Errorf("unmatched symbol must emit nothing: %v", got)
	}
	// No API name -> no tokens.
	if got := appendContractHints(nil, Candidate{}, contracts); len(got) != 0 {
		t.Errorf("empty APIName must emit nothing: %v", got)
	}
}
