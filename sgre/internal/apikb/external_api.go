package apikb

// External API semantic model (third-party library functions).
//
// The name-keyed maps in apikb.go answer one question each ("is this an
// allocator?", "may this return NULL?"). That is too coarse for library APIs
// whose allocation, release, ownership, and nullability semantics are
// independent dimensions: xmlXPathEvalExpression both allocates an object AND
// may return NULL; cJSON_AddItemToObject takes ownership only on success;
// cJSON_AddItemReferenceToObject looks like an add but must NOT transfer.
// ExternalAPISpec is the auditable record those dimensions live in.
//
// Maintenance guide (how to add a library):
//  1. Verify the semantics against the library's official API docs / headers
//     for a concrete version range; record it in Source. Do NOT infer from
//     the function name.
//  2. Pick the independent dimensions: Alloc (+OutParamIdx, ValidFrees,
//     AllowGenericFree, UnrestrictedRelease), Releases (+FreeArgIdx,
//     AcceptsNull), Ownership (+OwnArgIdx), RetNull, RetBorrow.
//  3. Uncertain semantics stay at the zero value (AllocNone / OwnershipNone /
//     RetNullUnknown): unknown must remain unknown, never a guessed rule.
//  4. Add rows to the table below, then extend the table-driven assertions in
//     apikb_external_api_test.go and the detector-level fixtures
//     (sgre/testdata/tc*.c) covering the positive, negative, and boundary
//     cases from docs/secguard-clang支持第三方库函数.md §9.
//
// Consumption points (keep this list in sync when adding queries):
//   - memory-leak: isMallocExpr / outputParamAllocVar (allocation),
//     findFrees (release + pairing), findEscapeLines (ownership transfer).
//   - null-deref: detectExternalCall / exprRetNullability /
//     filter_nullable_source (RetNull tiers) — via the Is* query shims.
//   - graph ownership RELEASE edges and the UAF/double-free detectors share
//     the same IsDeclaredDeallocator shim.
//
// Release-pairing rules (docs §6): an allocation made by a modeled API is
// validly released only by a call in ValidFrees, plus generic releases
// (free + project-registered deallocators + heuristic-only deallocators) when
// AllowGenericFree is set. malloc/calloc/realloc are UnrestrictedRelease
// (raw void* blocks; any deallocator releases them — keeps existing tests
// like tc116, which frees a malloc block through a _delete-suffixed mock,
// unchanged). Unmodeled allocators keep the pre-model behavior: every
// deallocator counts, no mismatch is reported.

// AllocKind describes how an external API produces a heap object.
type AllocKind uint8

const (
	// AllocNone: the API does not allocate a caller-owned object.
	AllocNone AllocKind = iota
	// AllocRet: the return value is a newly allocated object the caller owns.
	AllocRet
	// AllocOutParam: the object is written into an output parameter
	// (asprintf/vasprintf's char**); the return value is a status code.
	AllocOutParam
)

// OwnershipKind describes what happens to an argument's object ownership.
type OwnershipKind uint8

const (
	// OwnershipNone: the call does not change argument ownership.
	OwnershipNone OwnershipKind = iota
	// OwnershipTransferOnSuccess: the receiver takes over the argument's
	// object only when the call succeeds (return value checked path); on the
	// failure branch the caller still owns it and must release it.
	OwnershipTransferOnSuccess
	// OwnershipTransferAlways: the receiver unconditionally takes over
	// (used only where the library documents it).
	OwnershipTransferAlways
	// OwnershipBorrow: the call stores/returns a reference; ownership does
	// NOT transfer (cJSON_AddItemReferenceToArray/Object). This overrides
	// the `_add` escape heuristic, which would otherwise misread it.
	OwnershipBorrow
)

// RetNullKind describes the nullability of an API's return value.
type RetNullKind uint8

const (
	// RetNullUnknown: no verified contract; the existing fail-open tiers
	// (assumed-return / external-unknown) keep the result suspected.
	RetNullUnknown RetNullKind = iota
	// RetNullMay: documented maybe-NULL (same auto-confirm tier as strchr).
	RetNullMay
	// RetNullNever: guaranteed non-NULL return (abort-on-failure contracts).
	RetNullNever
)

// ExternalAPISpec is the auditable semantic record for one external API.
// All dimensions are independent: "returns a pointer" (RetNull != unknown),
// "returns a NEW allocation" (Alloc == AllocRet), and "transfers ownership"
// (Ownership) must never be collapsed into one boolean.
type ExternalAPISpec struct {
	// Library identifies the API's owner ("libxml2", "cjson", "libc").
	Library string
	// Source cites the verified reference and version range
	// ("libxml2-2.x-doc", "cJSON-1.7-readme", "POSIX").
	Source string

	// Alloc / OutParamIdx: allocation semantics. OutParamIdx is the char**
	// output argument index for AllocOutParam.
	Alloc       AllocKind
	OutParamIdx int
	// ValidFrees: the legal release calls for an object this API allocates.
	ValidFrees []string
	// AllowGenericFree: free() and project/heuristic deallocators also
	// validly release this API's allocations (true when the library itself
	// allocates with plain malloc — strdup, asprintf, cJSON_Print).
	AllowGenericFree bool
	// UnrestrictedRelease: ANY deallocator validly releases the object
	// (raw void* blocks: malloc/calloc/realloc).
	UnrestrictedRelease bool

	// Releases / FreeArgIdx / AcceptsNull: release semantics. FreeArgIdx is
	// the argument holding the released object. AcceptsNull records whether
	// calling the releaser with NULL is documented-safe; it is an audit
	// dimension — no detector branches on it yet — and stays false unless
	// the contract is explicit (free: C89; others: unverified).
	Releases    bool
	FreeArgIdx  int
	AcceptsNull bool

	// Ownership / OwnArgIdx: which argument's object ownership changes and
	// how. OwnArgIdx is meaningful only when Ownership != OwnershipNone.
	Ownership OwnershipKind
	OwnArgIdx int

	// RetNull: nullability of the return value.
	RetNull RetNullKind
	// RetBorrow: the return value points into an object owned elsewhere
	// (the document tree, the parent JSON item, the input string). A borrow
	// is never a fresh allocation and must not be freed by the caller.
	RetBorrow bool
}

// ExternalAPIs is the first-batch model (docs/secguard-clang支持第三方库函数.md
// §5). Every row is verified against the cited Source; version-sensitive
// semantics are conservatively modeled (see xmlSetNs) and unknowns stay
// unknown.
var ExternalAPIs = map[string]ExternalAPISpec{
	// ---- libc: raw heap blocks (unrestricted release) ----
	"malloc":  {Library: "libc", Source: "C89", Alloc: AllocRet, RetNull: RetNullMay, UnrestrictedRelease: true},
	"calloc":  {Library: "libc", Source: "C89", Alloc: AllocRet, RetNull: RetNullMay, UnrestrictedRelease: true},
	"realloc": {Library: "libc", Source: "C89", Alloc: AllocRet, RetNull: RetNullMay, UnrestrictedRelease: true},
	"free":    {Library: "libc", Source: "C89", Releases: true, FreeArgIdx: 0, AcceptsNull: true},

	// ---- libc: string/path duplication (malloc'd buffer, free() pairing;
	// a specialized library releaser on them is a mismatch, docs §5.3) ----
	"strdup":                 {Library: "libc", Source: "POSIX.1-2008", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"free"}, AllowGenericFree: true},
	"strndup":                {Library: "libc", Source: "POSIX.1-2008", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"free"}, AllowGenericFree: true},
	"wcsdup":                 {Library: "libc", Source: "POSIX.1-2008", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"free"}, AllowGenericFree: true},
	"getcwd":                 {Library: "libc", Source: "POSIX.1-2008", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"free"}, AllowGenericFree: true},
	"get_current_dir_name":   {Library: "libc", Source: "GNU", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"free"}, AllowGenericFree: true},
	"canonicalize_file_name": {Library: "libc", Source: "GNU", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"free"}, AllowGenericFree: true},

	// ---- libc: output-parameter allocators (status-code return; the
	// allocation exists only on the success branch, docs §5.3) ----
	"asprintf":  {Library: "libc", Source: "GNU", Alloc: AllocOutParam, OutParamIdx: 0, ValidFrees: []string{"free"}, AllowGenericFree: true},
	"vasprintf": {Library: "libc", Source: "GNU", Alloc: AllocOutParam, OutParamIdx: 0, ValidFrees: []string{"free"}, AllowGenericFree: true},
	"getline":   {Library: "libc", Source: "POSIX.1-2008", Alloc: AllocOutParam, OutParamIdx: 0, ValidFrees: []string{"free"}, AllowGenericFree: true},
	"getdelim":  {Library: "libc", Source: "POSIX.1-2008", Alloc: AllocOutParam, OutParamIdx: 0, ValidFrees: []string{"free"}, AllowGenericFree: true},

	// ---- libxml2: document/namespace allocation ----
	"xmlNewDoc":  {Library: "libxml2", Source: "libxml2-2.x-doc", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"xmlFreeDoc"}},
	"xmlNewNode": {Library: "libxml2", Source: "libxml2-2.x-doc", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"xmlFreeNode", "xmlFreeNodeList"}},
	"xmlNewNs":   {Library: "libxml2", Source: "libxml2-2.x-doc", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"xmlFreeNs"}},

	// ---- libxml2: document parsing (xmlDoc released by xmlFreeDoc only;
	// the tree's nodes are managed by the document, docs §5.1/§6) ----
	"xmlReadMemory": {Library: "libxml2", Source: "libxml2-2.x-doc", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"xmlFreeDoc"}},
	"xmlReadFile":   {Library: "libxml2", Source: "libxml2-2.x-doc", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"xmlFreeDoc"}},
	"xmlParseDoc":   {Library: "libxml2", Source: "libxml2-2.x-doc", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"xmlFreeDoc"}},
	"xmlReadDoc":    {Library: "libxml2", Source: "libxml2-2.x-doc", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"xmlFreeDoc"}},
	"xmlSAXParseDoc": {Library: "libxml2", Source: "libxml2-2.x-doc", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"xmlFreeDoc"}},

	// ---- libxml2: XPath objects (context and result object are DIFFERENT
	// object types with DIFFERENT releasers — never interchangeable, docs §5.1) ----
	"xmlXPathNewContext":     {Library: "libxml2", Source: "libxml2-2.x-doc", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"xmlXPathFreeContext"}},
	"xmlXPathEvalExpression": {Library: "libxml2", Source: "libxml2-2.x-doc", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"xmlXPathFreeObject"}},
	"xmlXPathEval":           {Library: "libxml2", Source: "libxml2-2.x-doc", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"xmlXPathFreeObject"}},
	"xmlXPathCompiledEval":   {Library: "libxml2", Source: "libxml2-2.x-doc", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"xmlXPathFreeObject"}},

	// ---- libxml2: releasers ----
	"xmlFreeDoc":            {Library: "libxml2", Source: "libxml2-2.x-doc", Releases: true, FreeArgIdx: 0},
	"xmlFreeNode":           {Library: "libxml2", Source: "libxml2-2.x-doc", Releases: true, FreeArgIdx: 0},
	"xmlFreeNodeList":       {Library: "libxml2", Source: "libxml2-2.x-doc", Releases: true, FreeArgIdx: 0},
	"xmlFreeNs":             {Library: "libxml2", Source: "libxml2-2.x-doc", Releases: true, FreeArgIdx: 0},
	"xmlXPathFreeContext":   {Library: "libxml2", Source: "libxml2-2.x-doc", Releases: true, FreeArgIdx: 0},
	"xmlXPathFreeObject":    {Library: "libxml2", Source: "libxml2-2.x-doc", Releases: true, FreeArgIdx: 0},
	"xmlFree":               {Library: "libxml2", Source: "libxml2-2.x-doc", Releases: true, FreeArgIdx: 0},

	// ---- libxml2: tree attach (ownership transfer). Success means a
	// non-NULL return (xmlAddChild/xmlAddSibling) or the document accepting
	// the root; on failure the caller keeps the node. The replaced old root
	// (returned by xmlDocSetRootElement) becomes caller-owned — modeling
	// return-carried ownership is out of scope for this batch and stays
	// unmodeled rather than guessed. ----
	"xmlDocSetRootElement": {Library: "libxml2", Source: "libxml2-2.x-doc", Ownership: OwnershipTransferOnSuccess, OwnArgIdx: 1, RetNull: RetNullMay},
	"xmlAddChild":          {Library: "libxml2", Source: "libxml2-2.x-doc", Ownership: OwnershipTransferOnSuccess, OwnArgIdx: 1, RetNull: RetNullMay},
	"xmlAddSibling":        {Library: "libxml2", Source: "libxml2-2.x-doc", Ownership: OwnershipTransferOnSuccess, OwnArgIdx: 1, RetNull: RetNullMay},
	// xmlSetNs: the namespace is managed by the node once attached.
	// Return type differs across libxml2 versions (void, later int), so the
	// transfer is modeled unconditionally — the conservative direction.
	"xmlSetNs": {Library: "libxml2", Source: "libxml2-2.x-doc", Ownership: OwnershipTransferAlways, OwnArgIdx: 1},

	// ---- libxml2: borrowed tree navigation (possibly NULL, never owned) ----
	"xmlDocGetRootElement":  {Library: "libxml2", Source: "libxml2-2.x-doc", RetNull: RetNullMay, RetBorrow: true},
	"xmlFirstElementChild":  {Library: "libxml2", Source: "libxml2-2.x-doc", RetNull: RetNullMay, RetBorrow: true},
	"xmlNextElementSibling": {Library: "libxml2", Source: "libxml2-2.x-doc", RetNull: RetNullMay, RetBorrow: true},

	// ---- cJSON: item creation (all Create* build a new item the caller
	// owns until it is attached to a parent; cJSON_Delete releases it) ----
	"cJSON_CreateObject":         {Library: "cjson", Source: "cJSON-1.7-readme", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"cJSON_Delete"}},
	"cJSON_CreateArray":          {Library: "cjson", Source: "cJSON-1.7-readme", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"cJSON_Delete"}},
	"cJSON_CreateString":         {Library: "cjson", Source: "cJSON-1.7-readme", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"cJSON_Delete"}},
	"cJSON_CreateNumber":         {Library: "cjson", Source: "cJSON-1.7-readme", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"cJSON_Delete"}},
	"cJSON_CreateDouble":         {Library: "cjson", Source: "cJSON-1.7-readme", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"cJSON_Delete"}},
	"cJSON_CreateBool":           {Library: "cjson", Source: "cJSON-1.7-readme", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"cJSON_Delete"}},
	"cJSON_CreateNull":           {Library: "cjson", Source: "cJSON-1.7-readme", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"cJSON_Delete"}},
	"cJSON_CreateTrue":           {Library: "cjson", Source: "cJSON-1.7-readme", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"cJSON_Delete"}},
	"cJSON_CreateFalse":          {Library: "cjson", Source: "cJSON-1.7-readme", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"cJSON_Delete"}},
	"cJSON_CreateRaw":            {Library: "cjson", Source: "cJSON-1.7-readme", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"cJSON_Delete"}},
	"cJSON_CreateArrayReference": {Library: "cjson", Source: "cJSON-1.7-readme", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"cJSON_Delete"}},
	"cJSON_CreateObjectReference": {Library: "cjson", Source: "cJSON-1.7-readme", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"cJSON_Delete"}},
	"cJSON_Duplicate":            {Library: "cjson", Source: "cJSON-1.7-readme", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"cJSON_Delete"}},
	"cJSON_Parse":                {Library: "cjson", Source: "cJSON-1.7-readme", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"cJSON_Delete"}},
	"cJSON_ParseWithLength":      {Library: "cjson", Source: "cJSON-1.7-readme", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"cJSON_Delete"}},
	"cJSON_ParseWithOpts":        {Library: "cjson", Source: "cJSON-1.7-readme", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"cJSON_Delete"}},

	// ---- cJSON: string printing (malloc'd string; cJSON_free is free by
	// default per the 1.7 readme, so generic free() is also legal) ----
	"cJSON_Print":             {Library: "cjson", Source: "cJSON-1.7-readme", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"cJSON_free"}, AllowGenericFree: true},
	"cJSON_PrintUnformatted":  {Library: "cjson", Source: "cJSON-1.7-readme", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"cJSON_free"}, AllowGenericFree: true},
	"cJSON_PrintBuffered":     {Library: "cjson", Source: "cJSON-1.7-readme", Alloc: AllocRet, RetNull: RetNullMay, ValidFrees: []string{"cJSON_free"}, AllowGenericFree: true},

	// ---- cJSON: releasers ----
	"cJSON_Delete": {Library: "cjson", Source: "cJSON-1.7-readme", Releases: true, FreeArgIdx: 0},
	"cJSON_free":   {Library: "cjson", Source: "cJSON-1.7-readme", Releases: true, FreeArgIdx: 0},

	// ---- cJSON: owning add (cJSON_bool return; 1 = success, ownership of
	// the ITEM argument transfers to the parent only then) vs reference add
	// (a reference item is created; the original's ownership does NOT move).
	// AddItemToObject(CS) takes the item as its THIRD argument. ----
	"cJSON_AddItemToArray":           {Library: "cjson", Source: "cJSON-1.7-readme", Ownership: OwnershipTransferOnSuccess, OwnArgIdx: 1},
	"cJSON_AddItemToObject":          {Library: "cjson", Source: "cJSON-1.7-readme", Ownership: OwnershipTransferOnSuccess, OwnArgIdx: 2},
	"cJSON_AddItemToObjectCS":        {Library: "cjson", Source: "cJSON-1.7-readme", Ownership: OwnershipTransferOnSuccess, OwnArgIdx: 2},
	"cJSON_AddItemReferenceToArray":  {Library: "cjson", Source: "cJSON-1.7-readme", Ownership: OwnershipBorrow},
	"cJSON_AddItemReferenceToObject": {Library: "cjson", Source: "cJSON-1.7-readme", Ownership: OwnershipBorrow},

	// ---- cJSON: borrowed lookups (possibly NULL — missing key / bad index;
	// case sensitivity differs between GetObjectItem variants, which does
	// not change the nullable-borrow semantics modeled here) ----
	"cJSON_GetObjectItem":               {Library: "cjson", Source: "cJSON-1.7-readme", RetNull: RetNullMay, RetBorrow: true},
	"cJSON_GetObjectItemCaseSensitive":  {Library: "cjson", Source: "cJSON-1.7-readme", RetNull: RetNullMay, RetBorrow: true},
	"cJSON_GetArrayItem":                {Library: "cjson", Source: "cJSON-1.7-readme", RetNull: RetNullMay, RetBorrow: true},
}

// ExternalAPISpecByName reports the model record for name, if modeled.
func ExternalAPISpecByName(name string) (ExternalAPISpec, bool) {
	s, ok := ExternalAPIs[name]
	return s, ok
}

// IsOutParamAllocator reports whether name allocates through an output
// parameter and, if so, the char** argument index the allocation is written
// into. It replaces the detector-local hardcoded asprintf/getline table so
// third-party out-param allocators can be added in one place.
func IsOutParamAllocator(name string) (int, bool) {
	s, ok := ExternalAPIs[name]
	if !ok || s.Alloc != AllocOutParam {
		return 0, false
	}
	return s.OutParamIdx, true
}

// ReleasePolicy is the allocator↔deallocator pairing rule for one allocator.
type ReleasePolicy struct {
	// Modeled is false for unmodeled allocators (custom wrappers, project
	// SDK functions): every deallocator counts — the pre-model behavior.
	Modeled bool
	// Unrestricted: any deallocator validly releases the object.
	Unrestricted bool
	// Valid holds the modeled legal releaser names.
	Valid map[string]bool
	// AllowGeneric: free(), project-registered deallocators, and
	// heuristic-only deallocators are also legal releasers.
	AllowGeneric bool
}

// AllocatorReleasePolicy returns the pairing rule for an allocation API.
func AllocatorReleasePolicy(allocAPI string) ReleasePolicy {
	s, ok := ExternalAPIs[allocAPI]
	if !ok || s.Alloc == AllocNone {
		return ReleasePolicy{}
	}
	p := ReleasePolicy{Modeled: true, Unrestricted: s.UnrestrictedRelease, AllowGeneric: s.AllowGenericFree}
	if len(s.ValidFrees) > 0 {
		p.Valid = make(map[string]bool, len(s.ValidFrees))
		for _, f := range s.ValidFrees {
			p.Valid[f] = true
		}
	}
	return p
}

// Releases reports whether releaseAPI validly releases an object allocated
// under the policy.
func (p ReleasePolicy) Releases(releaseAPI string) bool {
	if !p.Modeled {
		return true
	}
	if p.Unrestricted {
		return true
	}
	if p.Valid[releaseAPI] {
		return true
	}
	return p.AllowGeneric && isGenericRelease(releaseAPI)
}

// isGenericRelease reports whether releaseAPI is a generic (non-specialized)
// deallocator: free(), a project-registered deallocator, or a name that only
// the heuristic table matched. Specialized model entries (xmlFreeDoc,
// cJSON_Delete, ...) are not generic — using one on a foreign-family
// allocation is a mismatch.
func isGenericRelease(releaseAPI string) bool {
	if releaseAPI == "free" || extraDeallocators[releaseAPI] {
		return true
	}
	if _, modeled := ExternalAPIs[releaseAPI]; modeled {
		return false
	}
	return IsDeallocator(releaseAPI)
}

// EscapeOwnership reports the modeled ownership semantics of a call name:
// the kind, the argument index whose object is affected, and whether the
// name is modeled at all. Unmodeled names keep the `_add`/`_put` naming
// heuristic via IsEscapeFunction.
func EscapeOwnership(name string) (OwnershipKind, int, bool) {
	s, ok := ExternalAPIs[name]
	if !ok || s.Ownership == OwnershipNone {
		return OwnershipNone, 0, false
	}
	return s.Ownership, s.OwnArgIdx, true
}

// IsBorrowReturn reports whether name's return value is a borrowed pointer
// into an object owned elsewhere (never a fresh allocation, never freed by
// the caller).
func IsBorrowReturn(name string) bool {
	s, ok := ExternalAPIs[name]
	return ok && s.RetBorrow
}

// externalAPIAllocates / externalAPIReleases / externalAPIRetNull shims feed
// the legacy name-keyed queries so every existing consumer (memory-leak,
// null-deref tiers, UAF/double-free, graph ownership edges) picks up the
// model without each detector hardcoding its own copy of the list.
func externalAPIAllocates(name string) bool {
	s, ok := ExternalAPIs[name]
	return ok && s.Alloc != AllocNone
}

func externalAPIReleases(name string) bool {
	s, ok := ExternalAPIs[name]
	return ok && s.Releases
}