// Package apikb is the single source of truth for the security-relevant
// API knowledge used across detectors (internal/evidence) and the
// convergence pipeline (internal/planner). Previously this knowledge was
// duplicated in three places (evidence/safe_functions.go, planner/ranker.go,
// and an inline copy inside planner's SafeFunctionFilter), which drifted
// out of sync. Keep all of it here.
package apikb

// SafeFunctions are APIs whose use is already memory/injection safe
// (e.g. the *_s bounds-checked variants, parameterized SQL, mkstemp).
// Detectors should EXCLUDE these at the syntax level.
var SafeFunctions = map[string]bool{
	"memcpy_s":  true,
	"strcpy_s":  true,
	"sprintf_s": true,
	"strcat_s":  true,
	"snprintf":  true,
	"strncpy":   true,
	"strlcpy":   true,
	"strlcat":   true,
	// The exec* family replaces the process image without invoking a shell, so
	// none of them is a command-injection sink (no shell metacharacter
	// interpretation). Only shell-invoking calls (system, popen) are.
	"execve": true,
	"execv":  true,
	"execvp": true,
	"execl":  true,
	"execlp": true,
	"execle": true,

	"sqlite3_prepare_v2": true,
	"sqlite3_bind_text":  true,
	"sqlite3_bind_int":   true,
	"sqlite3_bind_blob":  true,
	"mkstemp":            true,
	"openat":             true,
}

// SafeWrappers are project-specific safe framework entry points.
var SafeWrappers = map[string]bool{
	"SafeCopy_copy":          true,
	"SafeCopy_strcpy":        true,
	"SafeQuery_prepare":      true,
	"SafeQuery_bind_text":    true,
	"SafeQuery_exec":         true,
	"ResourceHandle_create":  true,
	"ResourceHandle_destroy": true,
	"LockGuard_create":       true,
	"LockGuard_release":      true,
}

// BufferOverflowAPIs are calls whose length is caller-controlled and
// unchecked, and are therefore potential buffer overflows.
var BufferOverflowAPIs = map[string]bool{
	"memcpy":  true,
	"strcpy":  true,
	"strcat":  true,
	"strncpy": true,
	"strncat": true,
	"memmove": true,
	"gets":    true,
	"scanf":   true,
	"sscanf":  true,
	"fscanf":  true,
	"fread":   true,
	"read":    true,
	"recv":    true,
}

// InjectionAPIs are command/SQL sinks where tainted input is dangerous.
var InjectionAPIs = map[string]bool{
	"sprintf":          true,
	"snprintf":         true,
	"system":           true,
	"popen":            true,
	"execl":            true,
	"execlp":           true,
	"execle":           true,
	"execv":            true,
	"execvp":           true,
	"execve":           true,
	"sqlite3_exec":     true,
	"sqlite3_prepare":  true,
	"mysql_query":      true,
	"mysql_real_query": true,
	"PQexec":           true,
	"PQexecParams":     true,
	"CreateProcessA":   true,
	"CreateProcessW":   true,
	"CreateProcessAsA": true,
	"CreateProcessAsW": true,
	"ShellExecuteA":    true,
	"ShellExecuteW":    true,
	"ShellExecuteEx":   true,
	"ShellExecuteExA":  true,
	"ShellExecuteExW":  true,
}

// UnsafeFunctions maps an API name to the vulnerability category it implies.
var UnsafeFunctions = map[string]string{
	"memcpy":           "buffer_overflow",
	"strcpy":           "buffer_overflow",
	"strcat":           "buffer_overflow",
	"gets":             "buffer_overflow",
	"system":           "command_injection",
	"popen":            "command_injection",
	"sqlite3_exec":     "sql_injection",
	"CreateProcessA":   "command_injection",
	"CreateProcessW":   "command_injection",
	"CreateProcessAsA": "command_injection",
	"CreateProcessAsW": "command_injection",
	"ShellExecuteA":    "command_injection",
	"ShellExecuteW":    "command_injection",
	"ShellExecuteEx":   "command_injection",
	"ShellExecuteExA":  "command_injection",
	"ShellExecuteExW":  "command_injection",
	"execl":            "command_injection",
	"execlp":           "command_injection",
	"execle":           "command_injection",
	"execv":            "command_injection",
	"execvp":           "command_injection",
}

// CriticalAPIs, HighAPIs, MediumAPIs are the severity tiers used by the
// planner's ranker to order candidates.
var CriticalAPIs = map[string]bool{
	"system":           true,
	"popen":            true,
	"CreateProcessA":   true,
	"CreateProcessW":   true,
	"CreateProcessAsA": true,
	"CreateProcessAsW": true,
	"ShellExecuteA":    true,
	"ShellExecuteW":    true,
	"ShellExecuteEx":   true,
	"ShellExecuteExA":  true,
	"ShellExecuteExW":  true,
	"execl":            true,
	"execlp":           true,
	"execle":           true,
	"execv":            true,
	"execvp":           true,
	"execve":           true,
}

var HighAPIs = map[string]bool{
	"strcpy":  true,
	"strcat":  true,
	"sprintf": true,
	"gets":    true,
	"memcpy":  true,
}

var MediumAPIs = map[string]bool{
	"strncpy":  true,
	"strncat":  true,
	"snprintf": true,
	"fread":    true,
	"scanf":    true,
	"sscanf":   true,
	"fscanf":   true,
}

// IsSafeFunction reports whether name is a bounds/parameterization-safe API.
func IsSafeFunction(name string) bool { return SafeFunctions[name] }

// IsSafeWrapper reports whether name is a project safe framework entry point.
func IsSafeWrapper(name string) bool { return SafeWrappers[name] }

// BoundedCopyFunctions are APIs that take an explicit size argument but can
// still overflow if that size exceeds the destination's capacity. Unlike
// SafeFunctions (which are unconditionally safe), these need a runtime size
// check: strncpy(dst, src, n) overflows when n > sizeof(dst).
var BoundedCopyFunctions = map[string]bool{
	"strncpy": true,
	"strncat": true,
	"memcpy":  true,
	"memmove": true,
}

// IsBoundedCopy reports whether name is a bounded-copy API needing size check.
func IsBoundedCopy(name string) bool { return BoundedCopyFunctions[name] }

// SecureFuncSpec models an Annex K / Windows `_s` function's contract:
//
//	strcpy_s(destination, destination_capacity, source[, source_length])
//	    ├── destination            (arg 0)
//	    ├── destination_capacity   (arg CapArgIdx, always 1 for the standard layout)
//	    ├── source                 (arg 2)
//	    ├── source_length / count  (arg CountArgIdx, -1 when absent)
//	    ├── runtime_constraint_check
//	    └── constraint_violation_behavior
//
// The function is only safe when the declared capacity is truthful (equals the
// real buffer) AND the required size (count / source length) fits in it. The
// detector derives the two failure modes from this spec:
//
//   - capacity-lie:   destination_capacity (arg) > real buffer → overflow
//   - constraint-hit: required size (count/source) > destination_capacity (arg)
//
// gmtime_s / localtime_s take (result, time) with no capacity argument (they are
// thread-safe struct-return variants, not size-checked copies), and scanf_s /
// sscanf_s / fscanf_s use per-conversion width arguments instead of a single
// capacity, so neither family is represented here — they are handled separately.
type SecureFuncSpec struct {
	CapArgIdx   int // index of destination_capacity (always 1)
	CountArgIdx int // index of source_length/count, or -1 when absent
}

var SecureFunctions = map[string]SecureFuncSpec{
	"memcpy_s":    {CapArgIdx: 1, CountArgIdx: 3},
	"memmove_s":   {CapArgIdx: 1, CountArgIdx: 3},
	"memset_s":    {CapArgIdx: 1, CountArgIdx: 3},
	"strcpy_s":    {CapArgIdx: 1, CountArgIdx: -1},
	"strncpy_s":   {CapArgIdx: 1, CountArgIdx: 3},
	"strcat_s":    {CapArgIdx: 1, CountArgIdx: -1},
	"strncat_s":   {CapArgIdx: 1, CountArgIdx: 3},
	"sprintf_s":   {CapArgIdx: 1, CountArgIdx: -1},
	"snprintf_s":  {CapArgIdx: 1, CountArgIdx: 2},
	"vsprintf_s":  {CapArgIdx: 1, CountArgIdx: -1},
	"vsnprintf_s": {CapArgIdx: 1, CountArgIdx: 2},
	"asctime_s":   {CapArgIdx: 1, CountArgIdx: -1},
	"ctime_s":     {CapArgIdx: 1, CountArgIdx: -1},
}

// SecureFunctionSpec reports the contract spec of an Annex K `_s` function.
func SecureFunctionSpec(name string) (SecureFuncSpec, bool) {
	s, ok := SecureFunctions[name]
	return s, ok
}

// ScanfSecureFunctions are the `_s` input functions (scanf_s / sscanf_s /
// fscanf_s). Their "secure" contract differs from the copy `_s` functions:
// instead of a single destination-capacity argument, EVERY %s / %c / %[
// conversion that reads into a buffer is FOLLOWED by a buffer-size argument in
// the varargs (e.g. `scanf_s("%s", buf, (rsize_t)sizeof(buf))`). The map value
// is the argument index of the format string; the (buffer, size) pairs follow
// it, one per buffer-consuming conversion.
var ScanfSecureFunctions = map[string]int{
	"scanf_s":  0,
	"sscanf_s": 1,
	"fscanf_s": 1,
}

// ScanfSecureFormatArg reports whether name is an `_s` input function, and if
// so the argument index of its format string.
func ScanfSecureFormatArg(name string) (int, bool) {
	i, ok := ScanfSecureFunctions[name]
	return i, ok
}

// UnsafeFunctionCategory returns the vuln category implied by an unsafe API,
// or "" if the API is not in the unsafe set.
func UnsafeFunctionCategory(name string) string { return UnsafeFunctions[name] }

// SeverityValue returns a 0-100 severity weight for an API name, or a
// neutral baseline when the API is unknown.
func SeverityValue(apiName string) float64 {
	switch {
	case CriticalAPIs[apiName]:
		return 100
	case HighAPIs[apiName]:
		return 80
	case MediumAPIs[apiName]:
		return 60
	case apiName != "":
		return 40
	default:
		return 20
	}
}

// IsHighImpact reports whether apiName is a critical or high severity API.
func IsHighImpact(apiName string) bool {
	return CriticalAPIs[apiName] || HighAPIs[apiName]
}

// DerefArgFunctions lists library functions that unconditionally dereference
// (read or write through) one or more pointer arguments, together with the
// 0-based indices of those arguments. Passing a by-value pointer `p` at such an
// argument position dereferences `*p` inside the callee, so if control reaches
// the statement AFTER the call, `p` was non-null (otherwise the call would have
// faulted). The null-deref filter uses this as an implicit non-null kill:
//
//	head = get_head();        // may be null
//	memset_s(head, 0, 0, n);  // writes *head → head is provably non-null after
//	head->len = n;            // not a null-deref
//
// The list is deliberately restricted to string/memory routines whose
// dereference is unconditional. `strtok` is omitted because its first argument
// may legitimately be NULL (continuation), and `free`/`strerror`/`perror`
// accept NULL / non-pointer arguments.
var DerefArgFunctions = map[string][]int{
	"memset":      {0},
	"memset_s":    {0},
	"memcpy":      {0, 1},
	"memcpy_s":    {0, 2},
	"memmove":     {0, 1},
	"memmove_s":   {0, 2},
	"memcmp":      {0, 1},
	"strlen":      {0},
	"strnlen":     {0},
	"strcpy":      {0, 1},
	"strcpy_s":    {0, 2},
	"strncpy":     {0, 1},
	"strncpy_s":   {0, 2},
	"strcat":      {0, 1},
	"strcat_s":    {0, 2},
	"strncat":     {0, 1},
	"strncat_s":   {0, 2},
	"strlcpy":     {0, 1},
	"strlcat":     {0, 1},
	"strcmp":      {0, 1},
	"strncmp":     {0, 1},
	"strcasecmp":  {0, 1},
	"strncasecmp": {0, 1},
	"strchr":      {0},
	"strrchr":     {0},
	"strstr":      {0, 1},
	"sprintf":     {0, 1},
	"snprintf":    {0, 2},
	"sprintf_s":   {0, 2},
	"snprintf_s":  {0, 2},
	"vsprintf":    {0, 1},
	"vsnprintf":   {0, 2},
	"vsprintf_s":  {0, 2},
	"vsnprintf_s": {0, 2},
}

// DerefArgs returns the dereferenced argument indices of a library function, or
// (nil, false) when the function is not a known unconditional dereferencer.
func DerefArgs(name string) ([]int, bool) {
	idxs, ok := DerefArgFunctions[name]
	return idxs, ok
}

// NonZeroReturnFunctions are library functions whose integer return value is
// provably non-zero on every success path, so a division whose divisor is a
// direct call to one (`x / getpid()`) is safe without further analysis. The set
// is deliberately restricted to POSIX identity primitives (pid/uid/gid values are
// positive); a function that can return zero in a meaningful path (strlen, atoi,
// read, ...) is NOT listed, because treating it as non-zero would suppress a real
// divide-by-zero.
var NonZeroReturnFunctions = map[string]bool{
	"getpid":  true, // pid_t > 0
	"getppid": true, // parent pid > 0
	"getuid":  true, // real uid
	"geteuid": true, // effective uid
	"getgid":  true, // real gid
	"getegid": true, // effective gid
}

// NonZeroReturn reports whether a library function's return value is provably
// non-zero by contract.
func NonZeroReturn(name string) bool { return NonZeroReturnFunctions[name] }

// SQLFormatFuncs maps a string-formatting function to the index of its
// format-string argument. The Annex K _s variants insert a destination-
// capacity argument, shifting the format string one position later. These
// functions are taint channels: they interpolate runtime values into the
// destination buffer, so the destination inherits the taint of each variadic
// argument. The bounds check in the _s forms prevents overflow but does NOT
// sanitize the formatted bytes — attacker-controlled content still reaches the
// destination.
var SQLFormatFuncs = map[string]int{
	"sprintf":     1,
	"snprintf":    2,
	"sprintf_s":   2,
	"snprintf_s":  2,
	"vsprintf":    1,
	"vsnprintf":   2,
	"vsprintf_s":  2,
	"vsnprintf_s": 2,
}

// SQLFormatFuncFmtIdx reports the format-string argument index of a formatting
// function, or (0, false) when name is not a recognized format function.
func SQLFormatFuncFmtIdx(name string) (int, bool) {
	idx, ok := SQLFormatFuncs[name]
	return idx, ok
}

// SQLExecSinks maps a SQL execution API to the index of its SQL-string argument.
// The detector only flags a NON-LITERAL SQL argument, so the safe parameterized
// usage (a literal SQL string + sqlite3_bind_* / PQexecParams values) is skipped
// regardless of which API is listed here. sqlite3_prepare_v2 is excluded because
// it is listed in SafeFunctions; its legacy alias sqlite3_prepare is kept so a
// dynamically-built (interpolated) SQL string still reaches a sink. mysql_query /
// PQexec / PQexecParams execute the supplied SQL string and are injection sinks
// when that string is not a literal.
var SQLExecSinks = map[string]int{
	"sqlite3_exec":     1,
	"sqlite3_prepare":  1,
	"mysql_query":      1,
	"mysql_real_query": 1,
	"PQexec":           1,
	"PQexecParams":     1,
}

// SQLExecSinkIdx reports the SQL-string argument index of a SQL execution API,
// or (0, false) when name is not a recognized SQL sink.
func SQLExecSinkIdx(name string) (int, bool) {
	idx, ok := SQLExecSinks[name]
	return idx, ok
}
