package evidence

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestNullSource_ExtDeclReturnTypes verifies that indexing function declaration
// return types lets detectExternalCall filter external calls by return type:
// a call to an extern function returning a non-pointer type (int) must NOT
// produce a NULL_VALUE event, while a call to one returning a pointer type
// (my_struct_t*) must still fail-open and produce one.
//
// This is the core fix for the null-deref candidate explosion (1800+ candidates
// in production, 95%+ dismissed by AI): previously the indexer only indexed
// function definitions, so retTypes never contained external functions and
// detectExternalCall's return-type filter was a no-op for all externs.
func TestNullSource_ExtDeclReturnTypes(t *testing.T) {
	store := runOneDetector(t, "tc_null_deref_ext_decl.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewNullSourceDetector(s, p, l) })
	events, err := store.ListEventsByType(context.Background(), "NULL_VALUE")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}

	seenExtInt := false
	seenExtPtr := false
	for _, e := range events {
		var props struct {
			Function string `json:"function"`
			Origin   string `json:"origin"`
		}
		json.Unmarshal([]byte(e.Properties), &props)
		if props.Origin != "external_call" {
			continue
		}
		switch props.Function {
		case "ext_int_func":
			seenExtInt = true
		case "ext_ptr_func":
			seenExtPtr = true
		}
	}

	if seenExtInt {
		t.Error("ext_int_func (returns int) produced an external_call NULL_VALUE event — a non-pointer return type can never be NULL")
	}
	if !seenExtPtr {
		t.Error("ext_ptr_func (returns my_struct_t*) did NOT produce an external_call NULL_VALUE event — a pointer return type must fail-open")
	}
}
