package planner

import (
	"strings"
	"testing"
)

func TestBuildHint(t *testing.T) {
	dbz := &VulnTypeSpec{Name: "divide-by-zero"}
	uninit := &VulnTypeSpec{Name: "uninit"}
	iof := &VulnTypeSpec{Name: "integer-overflow"}
	nil2 := &VulnTypeSpec{Name: "null-deref"}
	cm := &VulnTypeSpec{Name: "crypto-misuse"}
	bo := &VulnTypeSpec{Name: "buffer-overflow"}
	oob := &VulnTypeSpec{Name: "out-of-bounds"}
	ml := &VulnTypeSpec{Name: "memory-leak"}
	rl := &VulnTypeSpec{Name: "resource-leak"}
	dangerous := &VulnTypeSpec{Name: "dangerous-function"}
	cases := []struct {
		name string
		c    Candidate
		spec *VulnTypeSpec
		want string
	}{
		{"certain null with source line", Candidate{SourceLine: 10, HasDefiniteNull: true}, nil, "src@10 certain-null"},
		{"maybe null with source line", Candidate{SourceLine: 20, HasNullableSource: true}, nil, "src@20 maybe-null"},
		{"taint source", Candidate{HasTaintSource: true}, nil, "tainted"},
		{"weak guard", Candidate{GuardStrength: "weak"}, nil, "weak-guard"},
		{"no flow facts", Candidate{}, nil, "—"},
		{"taint wins over null tier", Candidate{HasNullableSource: true, HasTaintSource: true}, nil, "maybe-null tainted"},
		{"divide-by-zero bare divisor", Candidate{VariableName: "n"}, dbz, "divisor@bare"},
		{"divide-by-zero call divisor", Candidate{VariableName: "get_count()"}, dbz, "divisor@call"},
		{"divide-by-zero compound divisor", Candidate{VariableName: "(a - b)"}, dbz, "divisor@compound"},
		{"divide-by-zero field divisor", Candidate{VariableName: "graph->gran_time"}, dbz, "divisor@field"},
		{"divide-by-zero global divisor", Candidate{VariableName: "g_count"}, dbz, "divisor@global"},
		{"api and category", Candidate{APIName: "memcpy", Category: "buffer_overflow"}, nil, "api@memcpy cat@buffer_overflow"},
		{"dangerous-function bounded const size", Candidate{APIName: "memcpy", Category: "unsafe_memory", SizeHint: "16", SizeKind: "const"}, dangerous, "size@16 size-kind@const api@memcpy cat@unsafe_memory"},
		{"dangerous-function variable size", Candidate{APIName: "memcpy", Category: "unsafe_memory", SizeHint: "n", SizeKind: "var"}, dangerous, "size@n size-kind@var api@memcpy cat@unsafe_memory"},
		{"uninit certain", Candidate{SuspicionLevel: "confirmed"}, uninit, "certain-uninit"},
		// null-deref states certainty through the null@<tier> token instead of
		// the shared certain-null/maybe-null pair, plus guard@none at the tail.
		{"null-deref cfg-proof", Candidate{SourceLine: 5, NullOriginTier: "cfg-proof"}, nil2, "null@cfg-proof src@5 guard@none"},
		{"null-deref malloc-fail with callee", Candidate{SourceLine: 5, NullOriginTier: "malloc-fail", IsCallResultDeref: true, CalleeDefFile: "src/util.c", CalleeDefLine: 42}, nil2, "null@malloc-fail callee@util.c:42 src@5 guard@none"},
		{"null-deref caller-arg", Candidate{NullOriginTier: "caller-arg"}, nil2, "null@caller-arg guard@none"},
		{"null-deref caller-arg with witness", Candidate{NullOriginTier: "caller-arg", CallerNullDetail: "caller foo passes NULL"}, nil2, "null@caller-arg caller-null@caller foo passes NULL guard@none"},
		{"null-deref external-unknown", Candidate{NullOriginTier: "external-unknown"}, nil2, "null@external-unknown guard@none"},
		{"uninit maybe", Candidate{SuspicionLevel: "suspected"}, uninit, "maybe-uninit"},
		{"integer-overflow unsigned sub unguarded", Candidate{Category: "unsigned_sub_underflow"}, iof, "guard@none cat@unsigned_sub_underflow"},
		{"integer-overflow unsigned sub provenance", Candidate{Category: "unsigned_sub_underflow", LHSKind: "param", RHSKind: "local", SubRHSInfluenced: true, SubSink: "call_arg"}, iof, "lhs@param rhs@local rhs-influenced sink@call_arg guard@none cat@unsigned_sub_underflow"},
		{"integer-overflow size calc (no guard tag)", Candidate{Category: "size_calc_overflow"}, iof, "cat@size_calc_overflow"},
		{"unchecked-return contract known", Candidate{ContractKnown: true, APIName: "malloc", Category: "unchecked_return"}, &VulnTypeSpec{Name: "unchecked-return"}, "contract@known api@malloc cat@unchecked_return"},
		{"unchecked-return contract unknown", Candidate{ContractKnown: false, APIName: "my_alloc", Category: "unchecked_return"}, &VulnTypeSpec{Name: "unchecked-return"}, "contract@unknown api@my_alloc cat@unchecked_return"},
		{"unchecked-return contract unknown with callee def", Candidate{ContractKnown: false, APIName: "obj_pool_new", Category: "unchecked_return", CalleeDefFile: "/srv/app/pool.c", CalleeDefLine: 42}, &VulnTypeSpec{Name: "unchecked-return"}, "contract@unknown callee@pool.c:42 api@obj_pool_new cat@unchecked_return"},
		{"unchecked-return contract known ignores callee def", Candidate{ContractKnown: true, APIName: "obj_pool_new", Category: "unchecked_return", CalleeDefFile: "/srv/app/pool.c", CalleeDefLine: 42}, &VulnTypeSpec{Name: "unchecked-return"}, "contract@known api@obj_pool_new cat@unchecked_return"},
		{"race shared data race", Candidate{Category: "shared_data_race", ThreadFunctions: "thread_race", ThreadInstances: 2, WriteLine: 15}, &VulnTypeSpec{Name: "race-condition"}, "threads@thread_race instances@2 write@15 cat@shared_data_race"},
		{"race toctou shared state", Candidate{Category: "toctou_shared_state", Mutex: "g_mutex", LockLine: 42, UnlockLine: 44}, &VulnTypeSpec{Name: "race-condition"}, "mutex@g_mutex lock@42-44 cat@toctou_shared_state"},
		{"race toctou", Candidate{Category: "toctou", CheckFunction: "access", UseFunction: "fopen", CheckPathArg: "path"}, &VulnTypeSpec{Name: "race-condition"}, "check@access→use@fopen arg@path cat@toctou"},
		{"double-free may-free", Candidate{Category: "double_free", FirstFree: 117, SecondFree: 123, MayFree: true}, &VulnTypeSpec{Name: "double-free"}, "free@117,123 may-free cat@double_free"},
		{"crypto-misuse reason and key size", Candidate{CryptoReason: "DES is weak (56-bit key)", CryptoKeySize: 7, Category: "undersized_key"}, cm, "reason@DES is weak (56-bit key) key-size@7 cat@undersized_key"},
		{"crypto-misuse reason only", Candidate{CryptoReason: "MD5 is cryptographically broken", Category: "weak_algorithm"}, cm, "reason@MD5 is cryptographically broken cat@weak_algorithm"},
		{"buffer-overflow constant index", Candidate{Array: "buf", Size: 16, Index: "20", Category: "array_oob_write"}, bo, "buf@buf cap@16 idx@20 cat@array_oob_write"},
		{"buffer-overflow variable copy size", Candidate{Array: "dst", Size: 64, CopySize: "n", Category: "bounded_copy_var_size"}, bo, "buf@dst cap@64 idx@n cat@bounded_copy_var_size"},
		{"buffer-overflow secure lying capacity", Candidate{Array: "dst", Size: 64, SizeArgument: "128", Category: "secure_copy_overflow"}, bo, "buf@dst cap@64 idx@128 cat@secure_copy_overflow"},
		{"buffer-overflow secure var size", Candidate{Array: "dst", Size: 64, SizeArgument: "n", Category: "secure_copy_var_size"}, bo, "buf@dst cap@64 idx@n cat@secure_copy_var_size"},
		{"buffer-overflow generic field-array strcpy", Candidate{Array: "log->id", Size: 8, Category: "buffer_overflow"}, bo, "buf@log->id cap@8 cat@buffer_overflow"},
		{"buffer-overflow generic read variable count", Candidate{Array: "rbuf", Size: 32, CopySize: "n", Category: "buffer_overflow"}, bo, "buf@rbuf cap@32 idx@n cat@buffer_overflow"},
		{"buffer-overflow copy size whitespace compacted", Candidate{Array: "dst", Size: 64, CopySize: "n + 1", Category: "bounded_copy_var_size"}, bo, "buf@dst cap@64 idx@n+1 cat@bounded_copy_var_size"},
		{"buffer-overflow bounded source", Candidate{Array: "g_dst", Size: 128, SrcCapacity: 128, APIName: "strcpy", Category: "buffer_overflow"}, bo, "buf@g_dst cap@128 src-cap@128 api@strcpy cat@buffer_overflow"},
		{"out-of-bounds constant read", Candidate{Array: "data", Size: 8, Index: "12", Category: "array_oob_read"}, oob, "buf@data cap@8 idx@12 cat@array_oob_read"},
		{"memory-leak definite no channel", Candidate{Line: 12, DefiniteLeak: true, LeakEscapeKind: "none", APIName: "malloc"}, ml, "alloc@12 leak@definite escape@none api@malloc"},
		{"memory-leak conditional store bypass", Candidate{Line: 12, LeakEscapeKind: "store", LeakFreeLines: "30,45"}, ml, "alloc@12 leak@conditional escape@store free@30,45"},
		{"memory-leak external API family mismatch", Candidate{Line: 18, LeakEscapeKind: "none", LeakFreeMismatch: "xmlXPathFreeContext:24", APIName: "xmlXPathEvalExpression"}, ml, "alloc@18 leak@conditional escape@none free-mismatch@xmlXPathFreeContext:24 api@xmlXPathEvalExpression"},
		{"memory-leak conditional ownership transfer", Candidate{Line: 15, LeakEscapeKind: "none", LeakTransferConditional: "cJSON_AddItemToObject:19", APIName: "cJSON_CreateString"}, ml, "alloc@15 leak@conditional escape@none transfer-cond@cJSON_AddItemToObject:19 api@cJSON_CreateString"},
		{"memory-leak free on borrowed pointer", Candidate{Line: 21, LeakEscapeKind: "none", LeakFreeOnBorrow: "cJSON_Delete", APIName: "cJSON_GetObjectItem"}, ml, "alloc@21 leak@conditional escape@none free-on-borrow@cJSON_Delete api@cJSON_GetObjectItem"},
		{"resource-leak conditional return bypass", Candidate{Line: 8, LeakEscapeKind: "return", LeakFreeLines: "22", Category: "resource_acquire", APIName: "fopen"}, rl, "acquire@8 leak@conditional escape@return free@22 api@fopen cat@resource_acquire"},
		// B4 §3.5 fact contracts: each remaining type's hint carries its
		// decisive machine-proven facts so the classifier can judge from the
		// index row instead of opening the evidence file.
		{"divide-by-zero interval and callers", Candidate{VariableName: "count", DivisorInterval: "[0,100]", DivisorCallers: "3 direct call sites, 2 pass non-zero constants"}, dbz, "divisor@bare range@[0,100] callers@3 direct call sites, 2 pass non-zero constants"},
		{"uninit storage facts", Candidate{SuspicionLevel: "confirmed", Origin: "heap", DeclLine: 17}, uninit, "certain-uninit origin@heap decl@17"},
		{"uninit suspected with stack origin", Candidate{SuspicionLevel: "suspected", Origin: "stack", DeclLine: 4}, uninit, "maybe-uninit origin@stack decl@4"},
		// F4: the machine-proven write-path facts close the "trace the write
		// paths" burden from the row.
		{"uninit heap no in-function write", Candidate{SuspicionLevel: "suspected", Origin: "heap_uninit", DeclLine: 18, InitWrite: "none"}, uninit, "maybe-uninit origin@heap_uninit decl@18 init@unseen"},
		{"uninit heap with allocator name", Candidate{SuspicionLevel: "suspected", Origin: "heap_uninit", DeclLine: 18, InitWrite: "none", APIName: "listCreate"}, uninit, "maybe-uninit origin@heap_uninit decl@18 init@unseen api@listCreate"},
		{"uninit stack never-written", Candidate{SuspicionLevel: "suspected", Origin: "stack_uninit", DeclLine: 18, InitWrite: "none"}, uninit, "maybe-uninit origin@stack_uninit decl@18 init@none"},
		{"uninit loop-only write", Candidate{SuspicionLevel: "suspected", Origin: "stack_uninit", DeclLine: 32, InitWrite: "loop", InitWriteLine: 33}, uninit, "maybe-uninit origin@stack_uninit decl@32 init@33 may-skip"},
		{"uninit loop fact without line is dropped", Candidate{SuspicionLevel: "suspected", Origin: "stack_uninit", DeclLine: 32, InitWrite: "loop"}, uninit, "maybe-uninit origin@stack_uninit decl@32"},
		{"argument-type triple", Candidate{ExpectedType: "size_t", ActualType: "int", CastType: "size_t"}, &VulnTypeSpec{Name: "argument-type"}, "expected@size_t actual@int cast@size_t"},
		{"data-representation cast", Candidate{CastType: "unsigned int"}, &VulnTypeSpec{Name: "data-representation"}, "cast@unsigned int"},
		{"format-string argument no taint", Candidate{FormatArg: "user_fmt"}, &VulnTypeSpec{Name: "format-string"}, "fmt-arg@user_fmt taint@none"},
		{"format-string tainted argument", Candidate{FormatArg: "user_fmt", HasTaintSource: true}, &VulnTypeSpec{Name: "format-string"}, "fmt-arg@user_fmt tainted"},
		{"path-traversal argument no taint", Candidate{PathExpr: "rel_path"}, &VulnTypeSpec{Name: "path-traversal"}, "path-arg@rel_path taint@none"},
		{"hardcoded-secret masked shape", Candidate{SecretValue: "AKIAIOSFODNN7EXAMPLE"}, &VulnTypeSpec{Name: "hardcoded-secret"}, "value-shape@\"AKIA…\" (20 chars)"},
		{"hardcoded-secret short value fully masked", Candidate{SecretValue: "abcd"}, &VulnTypeSpec{Name: "hardcoded-secret"}, "value-shape@\"****\" (4 chars)"},
		{"signal-handler unsafe call", Candidate{VariableName: "fprintf", FunctionName: "on_signal"}, &VulnTypeSpec{Name: "signal-handler"}, "async-unsafe@fprintf"},
		{"implicit-contract facts", Candidate{Subject: "ctx", CountField: "ctx->len", EvidenceKind: "self"}, &VulnTypeSpec{Name: "implicit-contract"}, "subject@ctx count-field@ctx->len evidence-kind@self"},
		{"sizeof-misuse subject", Candidate{VariableName: "ptr"}, &VulnTypeSpec{Name: "sizeof-misuse"}, "subject@ptr"},
		{"double-free conditional helper", Candidate{Category: "double_free", FirstFree: 40, SecondFree: 52, MayFree: true, FirstCallee: "maybe_release"}, &VulnTypeSpec{Name: "double-free"}, "free@40,52 may-free cond@maybe_release cat@double_free"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildHint(tc.c, tc.spec); got != tc.want {
				t.Errorf("buildHint() = %q, want %q", got, tc.want)
			}
		})
	}
}
func TestNewEvidenceItem_UncheckedReturnContract(t *testing.T) {
	spec := &VulnTypeSpec{Name: "unchecked-return", EvidenceType: "UNCHECKED_RETURN", BuildEvidence: func(c Candidate) []EvidenceFragment { return nil }}

	c1 := Candidate{ContractKnown: true, FunctionName: "f", Line: 10}
	item1 := newEvidenceItem(c1, spec, "test.c")
	if item1.Contract != "known" {
		t.Errorf("contractKnown=true: Contract should be known, got %q", item1.Contract)
	}

	c2 := Candidate{ContractKnown: false, FunctionName: "f", Line: 10}
	item2 := newEvidenceItem(c2, spec, "test.c")
	if item2.Contract != "unknown" {
		t.Errorf("contractKnown=false: Contract should be unknown, got %q", item2.Contract)
	}
}

// E-03 regression: contract@unknown evidence must carry the callee's definition
// location (or an explicit "no body in scan") — the classifier's proof burden
// ("prove the callee returns a failure sentinel or dismiss") cannot be met from
// a ±8 window when the callee is a static factory in another file.
func TestBuildEvidence_UncheckedReturnCalleeDefinition(t *testing.T) {
	spec, err := GetVulnTypeSpec("unchecked-return")
	if err != nil {
		t.Fatal(err)
	}
	join := func(frags []EvidenceFragment) string {
		var sb strings.Builder
		for _, f := range frags {
			sb.WriteString(f.Detail)
			sb.WriteString("\n")
		}
		return sb.String()
	}

	def := join(spec.BuildEvidence(Candidate{
		APIName: "obj_pool_new", FunctionName: "handle", Line: 10,
		CalleeDefFile: "pool.c", CalleeDefLine: 42, CalleeDefSignature: "Obj *obj_pool_new(int n)",
	}))
	if !strings.Contains(def, "callee obj_pool_new is defined in the scan at pool.c:42") {
		t.Errorf("in-scan callee: evidence must carry the definition location:\n%s", def)
	}
	if !strings.Contains(def, "signature: Obj *obj_pool_new(int n)") {
		t.Errorf("in-scan callee: evidence must carry the callee signature:\n%s", def)
	}

	ext := join(spec.BuildEvidence(Candidate{APIName: "ext_buf_dup", FunctionName: "handle_ext", Line: 5}))
	if !strings.Contains(ext, "callee ext_buf_dup has no definition in the scan") {
		t.Errorf("external callee: evidence must say no definition in scan:\n%s", ext)
	}

	known := join(spec.BuildEvidence(Candidate{APIName: "malloc", FunctionName: "f", Line: 3, ContractKnown: true}))
	if strings.Contains(known, "callee_definition") || strings.Contains(known, "no definition in the scan") {
		t.Errorf("contract@known: callee-definition fragment must not appear:\n%s", known)
	}
}

// E-05, param half: taint that enters through a caller's argument has no
// in-function origin statement — the fragment must say where the taint enters
// instead of sending the classifier to hunt a source the window cannot hold.
func TestTaintSourceDetail_ParamOrigin(t *testing.T) {
	inj, err := GetVulnTypeSpec("injection")
	if err != nil {
		t.Fatal(err)
	}
	frags := inj.BuildEvidence(Candidate{HasTaintSource: true, FunctionName: "f", Line: 9})
	found := false
	for _, f := range frags {
		if f.Type == "taint_source" {
			found = true
			if !strings.Contains(f.Detail, "tainted parameter") || !strings.Contains(f.Detail, "CALLER") {
				t.Errorf("param-origin taint fragment must say the taint enters from a caller:\n%s", f.Detail)
			}
		}
	}
	if !found {
		t.Errorf("taint_source fragment missing: %+v", frags)
	}
}

// E-06 regression: the decisive source lines (free site, both frees, uninit
// declaration, racing write, unguarded dereference, null/taint origin) must
// reach the evidence item so the report can widen the Code Context window to
// cover the source→sink span.
func TestNewEvidenceItem_SourceLinesCollection(t *testing.T) {
	spec := &VulnTypeSpec{Name: "use-after-free", EvidenceType: "USE_AFTER_FREE", BuildEvidence: func(c Candidate) []EvidenceFragment { return nil }}
	uaf := newEvidenceItem(Candidate{FunctionName: "f", Line: 40, FreeLine: 12}, spec, "uaf.c")
	if len(uaf.SourceLines) != 1 || uaf.SourceLines[0] != 12 {
		t.Errorf("UAF SourceLines = %v, want [12]", uaf.SourceLines)
	}
	df := newEvidenceItem(Candidate{FunctionName: "g", Line: 9, FirstFree: 4, SecondFree: 9}, spec, "df.c")
	if len(df.SourceLines) != 2 || df.SourceLines[0] != 4 || df.SourceLines[1] != 9 {
		t.Errorf("DF SourceLines = %v, want [4 9]", df.SourceLines)
	}
	none := newEvidenceItem(Candidate{FunctionName: "h", Line: 3}, spec, "x.c")
	if len(none.SourceLines) != 0 {
		t.Errorf("no source facts: SourceLines = %v, want empty", none.SourceLines)
	}
}

// TestBuildHint_ApiBeforeFlowTokens pins E-08: api@ (the callee name) must sit
// right after the type-specific tokens and BEFORE the flow tokens (src@, null
// tier, tainted, ...) — the Hint cell is markdownCell-truncated at 120 chars,
// and unchecked-return's hints are the longest, so a tail position let the
// callee name be the first thing the truncation ate.
func TestBuildHint_ApiBeforeFlowTokens(t *testing.T) {
	// The nullable-origin tier is loaded by the nullable-source filter; a
	// Candidate that skipped it (tier empty) still carries the shared flow
	// tokens — and null-deref's guard@none (machine-verified absence) instead
	// of the flat maybe-null it no longer emits.
	got := buildHint(Candidate{
		APIName:           "obfuscated_pool_allocator_factory",
		Category:          "unchecked_return",
		SourceLine:        123,
		HasNullableSource: true,
	}, &VulnTypeSpec{Name: "null-deref"})
	want := "api@obfuscated_pool_allocator_factory cat@unchecked_return src@123 guard@none"
	if got != want {
		t.Errorf("buildHint() = %q, want %q", got, want)
	}
}

func TestNewEvidenceItem_ExpressionCarried(t *testing.T) {
	spec := &VulnTypeSpec{Name: "buffer-overflow", EvidenceType: "BUFFER_OVERFLOW", BuildEvidence: func(c Candidate) []EvidenceFragment { return nil }}
	item := newEvidenceItem(Candidate{
		FunctionName: "copy",
		Line:         7,
		Expression:   "memcpy(dst,\n  src,\n  n)",
	}, spec, "wrap.c")
	if item.Expression != "memcpy(dst,\n  src,\n  n)" {
		t.Errorf("EvidenceItem.Expression = %q, want the detector's full statement text", item.Expression)
	}
}
