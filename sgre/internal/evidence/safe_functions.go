package evidence

var safeFunctions = map[string]bool{
	"memcpy_s":  true,
	"strcpy_s":  true,
	"sprintf_s": true,
	"strcat_s":  true,
	"snprintf":  true,
	"strncpy":   true,
	"strlcpy":   true,
	"strlcat":   true,
	"execve":    true,

	"sqlite3_prepare_v2": true,
	"sqlite3_bind_text":  true,
	"sqlite3_bind_int":   true,
	"sqlite3_bind_blob":  true,
	"mkstemp":            true,
	"openat":             true,
}

var safeWrappers = map[string]bool{
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

func isSafeFunction(name string) bool {
	return safeFunctions[name]
}

func isSafeWrapper(name string) bool {
	return safeWrappers[name]
}

var bufferOverflowAPIs = map[string]bool{
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

var injectionAPIs = map[string]bool{
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

var unsafeFunctions = map[string]string{
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

func unsafeFunctionCategory(name string) string {
	return unsafeFunctions[name]
}
