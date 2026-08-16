package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/planner"
)

func (o *ScanOutput) writeReport(packages []*planner.PlanResult, indexSummary IndexSummary) error {
	var b strings.Builder

	b.WriteString("# SecGuard Security Scan Report\n\n")
	b.WriteString(fmt.Sprintf("**Scan ID:** %s\n", o.ScanID))
	b.WriteString(fmt.Sprintf("**Tool:** zhuque-secguard v0.1.0\n\n"))

	b.WriteString("## Summary\n\n")
	b.WriteString("| Metric | Value |\n")
	b.WriteString("|--------|-------|\n")
	b.WriteString(fmt.Sprintf("| Files indexed | %d |\n", indexSummary.FilesIndexed))
	b.WriteString(fmt.Sprintf("| Functions indexed | %d |\n", indexSummary.FunctionsIndexed))
	b.WriteString(fmt.Sprintf("| Functions in index | %d |\n", indexSummary.FunctionsInIndex))

	totalCandidates := 0
	for _, pkg := range packages {
		totalCandidates += len(pkg.Candidates)
	}
	b.WriteString(fmt.Sprintf("| Total candidates | %d |\n", totalCandidates))
	b.WriteString(fmt.Sprintf("| Vulnerability types | %d |\n\n", len(packages)))

	b.WriteString("## Candidates by Skill\n\n")
	b.WriteString("| Skill | CWE | Count |\n")
	b.WriteString("|-------|-----|-------|\n")
	for _, pkg := range packages {
		cwe := vulnToCWE[pkg.VulnerabilityType]
		if cwe == "" {
			cwe = "CWE-Other"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %d |\n", pkg.VulnerabilityType, cwe, len(pkg.Candidates)))
	}
	b.WriteString("\n")

	for _, pkg := range packages {
		if len(pkg.Candidates) == 0 {
			continue
		}
		cwe := vulnToCWE[pkg.VulnerabilityType]
		if cwe == "" {
			cwe = "CWE-Other"
		}
		b.WriteString(fmt.Sprintf("## %s (%s)\n\n", pkg.VulnerabilityType, cwe))
		b.WriteString(fmt.Sprintf("| # | Function | File:Line | Variable | Suspicion |\n"))
		b.WriteString(fmt.Sprintf("|---|----------|-----------|----------|----------|\n"))
		for i, c := range pkg.Candidates {
			fileShort := shortFile(c.Target.File)
			b.WriteString(fmt.Sprintf("| %d | %s | %s:%d | %s | %s |\n",
				i+1, c.Target.Function, fileShort, c.Target.Line, c.Target.Variable, c.SuspicionLevel))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Output Files\n\n")
	b.WriteString(fmt.Sprintf("- SARIF: `%s`\n", o.SarifPath))
	b.WriteString(fmt.Sprintf("- Per-finding details: `<vuln-type>/<NNN>_<file>_<line>.md`\n"))
	b.WriteString(fmt.Sprintf("- Database: `.sgre/sgre.db`\n"))

	return os.WriteFile(o.ReportPath, []byte(b.String()), 0644)
}

func (o *ScanOutput) writePerFinding(packages []*planner.PlanResult) error {
	for _, pkg := range packages {
		if len(pkg.Candidates) == 0 {
			continue
		}

		dir := filepath.Join(o.ScanDir, pkg.VulnerabilityType)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}

		for i, c := range pkg.Candidates {
			cwe := vulnToCWE[pkg.VulnerabilityType]
			if cwe == "" {
				cwe = "CWE-Other"
			}

			fileShort := shortFile(c.Target.File)
			safeName := sanitizeFilename(fileShort)
			filename := fmt.Sprintf("%03d_%s_%d.md", i+1, safeName, c.Target.Line)
			path := filepath.Join(dir, filename)

			var b strings.Builder
			b.WriteString(fmt.Sprintf("# %s in %s\n\n", title(pkg.VulnerabilityType), c.Target.Function))
			b.WriteString(fmt.Sprintf("**CWE:** %s\n\n", cwe))

			b.WriteString("## Location\n\n")
			b.WriteString(fmt.Sprintf("- **File:** `%s:%d`\n", c.Target.File, c.Target.Line))
			b.WriteString(fmt.Sprintf("- **Function:** `%s`\n", c.Target.Function))
			if c.Target.Variable != "" {
				b.WriteString(fmt.Sprintf("- **Variable:** `%s`\n", c.Target.Variable))
			}
			b.WriteString("\n")

			b.WriteString("## Evidence\n\n")
			for _, e := range c.Evidence {
				b.WriteString(fmt.Sprintf("- **%s:** %s\n", e.Type, e.Detail))
			}
			b.WriteString("\n")

			b.WriteString("## Classification\n\n")
			b.WriteString(fmt.Sprintf("- **Suspicion Level:** %s\n", c.SuspicionLevel))
			b.WriteString("- **Status:** _pending_ (awaiting agent classification)\n")
			b.WriteString("\n")

			b.WriteString("## Fix Suggestion\n\n")
			b.WriteString(generateFixSuggestion(pkg.VulnerabilityType, cwe, c))

			if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
				return err
			}
		}
	}
	return nil
}

func shortFile(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) <= 2 {
		return path
	}
	return strings.Join(parts[len(parts)-2:], "/")
}

func sanitizeFilename(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ".", "_")
	return s
}

func title(s string) string {
	words := strings.Split(s, "-")
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

func generateFixSuggestion(vulnType, cwe string, c planner.EvidenceItem) string {
	varName := c.Target.Variable
	if varName == "" {
		varName = "the variable"
	}
	funcName := c.Target.Function

	switch vulnType {
	case "null-deref":
		return fmt.Sprintf(
			"Add a NULL check before dereferencing `%s` in `%s`:\n\n"+
				"```c\n"+
				"if (%s == NULL) {\n"+
				"    // handle error: return, log, or assert\n"+
				"    return -1;\n"+
				"}\n"+
				"// safe to use %s here\n"+
				"```\n\n"+
				"Also ensure `%s` is properly initialized on all code paths leading to this point.\n",
			varName, funcName, varName, varName, varName)

	case "buffer-overflow":
		return fmt.Sprintf(
			"Validate the buffer size before accessing `%s` in `%s`:\n\n"+
				"```c\n"+
				"// Check bounds before write/read\n"+
				"if (offset + access_size > buffer_capacity) {\n"+
				"    return -1;  // or clamp the size\n"+
				"}\n"+
				"```\n\n"+
				"Prefer safe alternatives: `memcpy_s`, `strncpy_s`, `snprintf` instead of\n"+
				"`memcpy`, `strcpy`, `sprintf`. If using loop-based access, add an explicit\n"+
				"upper-bound check on the loop index.\n",
			varName, funcName)

	case "memory-leak":
		return fmt.Sprintf(
			"Ensure `%s` is freed on **all** code paths in `%s`, including error paths:\n\n"+
				"```c\n"+
				"char *%s = malloc(size);\n"+
				"if (!%s) return -1;\n"+
				"// ... use %s ...\n"+
				"free(%s);\n"+
				"%s = NULL;\n"+
				"return 0;\n"+
				"```\n\n"+
				"For complex control flow, use a `goto cleanup` pattern or RAII-style\n"+
				"create/destroy wrapper functions to guarantee release.\n",
			varName, funcName, varName, varName, varName, varName, varName)

	case "injection":
		checkText := strings.ToLower(c.Target.Variable)
		for _, e := range c.Evidence {
			checkText += " " + strings.ToLower(e.Detail)
		}
		if strings.Contains(checkText, "sql") || strings.Contains(checkText, "sqlite") ||
			strings.Contains(checkText, "query") {
			return fmt.Sprintf(
				"Use parameterized queries instead of string concatenation in `%s`:\n\n"+
					"```c\n"+
					"sqlite3_stmt *stmt;\n"+
					"sqlite3_prepare_v2(db, \"SELECT * FROM t WHERE id = ?\", -1, &stmt, NULL);\n"+
					"sqlite3_bind_text(stmt, 1, user_input, -1, SQLITE_STATIC);\n"+
					"sqlite3_step(stmt);\n"+
					"sqlite3_finalize(stmt);\n"+
					"```\n\n"+
					"Never interpolate user-controlled data into SQL query strings.\n",
				funcName)
		}
		return fmt.Sprintf(
			"Avoid passing user-controlled input to command execution functions in `%s`.\n\n"+
				"```c\n"+
				"// BAD:  system(user_input);\n"+
				"// GOOD: use execve() with explicit argument array\n"+
				"char *argv[] = {\"/bin/ls\", user_input, NULL};\n"+
				"execve(\"/bin/ls\", argv, NULL);\n"+
				"```\n\n"+
				"If shell invocation is unavoidable, strictly validate/whitelist the input\n"+
				"and escape shell metacharacters before use.\n",
			funcName)

	case "resource-leak":
		return fmt.Sprintf(
			"Ensure the resource acquired in `%s` is released on **all** code paths,\n"+
				"including error and early-return paths:\n\n"+
				"```c\n"+
				"FILE *f = fopen(path, \"r\");\n"+
				"if (!f) return -1;\n"+
				"// ... use f ...\n"+
				"fclose(f);\n"+
				"return 0;\n"+
				"```\n\n"+
				"For handles with create/destroy or acquire/release semantics, pair every\n"+
				"acquire with a matching release. Use `goto cleanup` for multi-resource\n"+
				"functions.\n",
			funcName)

	case "uninit":
		return fmt.Sprintf(
			"Initialize `%s` at declaration or ensure it is assigned before first use\n"+
				"in `%s`:\n\n"+
				"```c\n"+
				"// Option 1: initialize at declaration\n"+
				"int %s = 0;\n\n"+
				"// Option 2: explicit initialization before use\n"+
				"%s = compute_value();\n"+
				"if (error) return -1;\n"+
				"// now safe to use %s\n"+
				"```\n\n"+
				"For struct members, use `memset(&%s, 0, sizeof(%s))` or designated\n"+
				"initializers to zero-fill before use.\n",
			varName, funcName, varName, varName, varName, varName, varName)

	case "use-after-free":
		return fmt.Sprintf(
			"After freeing `%s` in `%s`, set the pointer to NULL to prevent\n"+
				"use-after-free:\n\n"+
				"```c\n"+
				"free(%s);\n"+
				"%s = NULL;  // prevents accidental reuse\n"+
				"```\n\n"+
				"Audit all code paths to ensure no aliasing pointer still references the\n"+
				"freed memory. Consider using a ownership-tracking wrapper or static analyzer\n"+
				"to enforce lifetime discipline.\n",
			varName, funcName, varName, varName)

	case "double-free":
		return fmt.Sprintf(
			"Prevent double-free of `%s` in `%s` by setting the pointer to NULL\n"+
				"after the first free:\n\n"+
				"```c\n"+
				"free(%s);\n"+
				"%s = NULL;  // subsequent free(NULL) is a safe no-op\n"+
				"```\n\n"+
				"For complex ownership, track the allocation state explicitly with a flag\n"+
				"or use a wrapper that checks `if (ptr != NULL)` before freeing.\n",
			varName, funcName, varName, varName)

	case "format-string":
		return fmt.Sprintf(
			"Use a constant format string in `%s`; never let user input be the format\n"+
				"argument:\n\n"+
				"```c\n"+
				"// BAD:  printf(user_input);\n"+
				"// GOOD: printf(\"%%s\", user_input);\n"+
				"```\n\n"+
				"If dynamic formatting is needed, use `vsnprintf` with a fixed-size buffer\n"+
				"and a caller-specified format string that is validated against a whitelist.\n",
			funcName)

	case "integer-overflow":
		return fmt.Sprintf(
			"Check for integer overflow before using the result in memory allocation\n"+
				"or buffer operations in `%s`:\n\n"+
				"```c\n"+
				"// Check a + b > SIZE_MAX before allocating\n"+
				"if (a > SIZE_MAX - b) {\n"+
				"    return NULL;  // overflow would occur\n"+
				"}\n"+
				"size_t total = a + b;\n"+
				"char *buf = malloc(total);\n"+
				"```\n\n"+
				"Use `size_t` for sizes (never `int`), and prefer checked-arithmetic\n"+
				"helpers like `__builtin_add_overflow` (GCC/Clang) or manual bounds\n"+
				"checks. Clamp `count * elem_size` products before passing to `malloc`/`memcpy`.\n",
			funcName)

	case "race-condition":
		return fmt.Sprintf(
			"Eliminate the time-of-check-to-time-of-use (TOCTOU) race in `%s` by\n"+
				"performing check and use atomically:\n\n"+
				"```c\n"+
				"// BAD: if (access(path, R_OK) == 0) { f = fopen(path, \"r\"); }\n"+
				"// GOOD: open the file directly and check the fd\n"+
				"int fd = open(path, O_RDONLY);\n"+
				"if (fd < 0) { /* handle */ }\n"+
				"FILE *f = fdopen(fd, \"r\");\n"+
				"```\n\n"+
				"For shared state, protect check-then-act sequences with a mutex:\n"+
				"lock before the check and hold the lock through the mutation. Avoid\n"+
				"`access()` + `fopen()` patterns; use `fopen()` and check the result.\n",
			funcName)

	case "hardcoded-secret":
		return fmt.Sprintf(
			"Remove the hardcoded credential from `%s` and load it from a secure\n"+
				"source at runtime:\n\n"+
				"```c\n"+
				"// BAD:  const char *password = \"admin123\";\n"+
				"// GOOD: read from env var, vault, or config file with restricted perms\n"+
				"const char *password = getenv(\"APP_PASSWORD\"));\n"+
				"if (!password) { return -1; }\n"+
				"```\n\n"+
				"Store secrets in a secrets manager (HashiCorp Vault, cloud KMS) or a\n"+
				"file with `0600` permissions outside the repo. Never commit credentials\n"+
				"to source control. Rotate any credentials that were previously hardcoded.\n",
			funcName)

	case "deadlock":
		return fmt.Sprintf(
			"Eliminate the lock-order inversion in `%s` by establishing a consistent\n"+
				"global lock acquisition order:\n\n"+
				"```c\n"+
				"// Rule: always acquire lockA before lockB\n"+
				"pthread_mutex_lock(&lockA);\n"+
				"pthread_mutex_lock(&lockB);\n"+
				"// ... critical section ...\n"+
				"pthread_mutex_unlock(&lockB);\n"+
				"pthread_mutex_unlock(&lockA);\n"+
				"```\n\n"+
				"Document the lock hierarchy and enforce it with static analysis or\n"+
				"runtime lock-order sanitizers (e.g., TSan). Consider using a single\n"+
				"coarse-grained lock if the ordering is hard to maintain, or refactor\n"+
				"to avoid nested locking.\n",
			funcName)

	case "crypto-misuse":
		return fmt.Sprintf(
			"Replace the weak cryptographic primitive in `%s` with a modern,\n"+
				"industry-standard alternative:\n\n"+
				"```c\n"+
				"// BAD:  DES_set_key_unchecked(&key, &schedule);\n"+
				"// GOOD: use AES-256 via a vetted library (OpenSSL EVP)\n"+
				"EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();\n"+
				"EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);\n"+
				"```\n\n"+
				"Specific replacements: DES/3DES → AES-256; MD5/SHA1 → SHA-256 or SHA-3;\n"+
				"rand() → cryptographic PRNG (getrandom, CryptGenRandom); RC4 → AES.\n"+
				"Use keys of at least 128 bits (256 recommended for long-term security).\n",
			funcName)

	default:
		return "Review the evidence above and apply the appropriate mitigation for this\n" +
			"vulnerability class. Consult the CWE documentation for detailed guidance.\n"
	}
}
