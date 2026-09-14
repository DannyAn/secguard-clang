package indexer

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/log"
)

// DefaultExcludeDirs are the directory basenames skipped by default when no
// explicit --exclude is given. They are vendored third-party / build / test /
// fuzzing directories whose contents are not the audited project's own
// production code — scanning them floods the convergence pipeline with noise
// (redis's deps/ + tests/ produced the bulk of null-deref/uninit candidates).
var DefaultExcludeDirs = []string{
	"deps", "third_party", "third-party", "vendor", "external", "node_modules",
	"tests", "test", "fuzzing", "contrib", "examples",
}

// WalkCFiles walks rootPath and returns every .c/.h file, skipping any
// directory whose basename is in exclude (case-insensitive) and any directory
// at or under one of the resolved excludePaths. A skipped directory is pruned
// entirely via filepath.SkipDir. An unreadable SUB-path (permission denied,
// macOS TCC, NFS blip) is logged and skipped — it never aborts the whole scan;
// only a failure on rootPath itself is fatal.
//
// excludePaths entries are directory paths (e.g. "./svc/src/bak/" from
// secguard.toml [exclude] paths). A relative entry is resolved against
// rootPath (the scan target), not the process working directory, so
// `secguard scan ./src` with "svc/bak" prunes ./src/svc/bak.
func WalkCFiles(rootPath string, exclude []string, excludePaths []string, logger *log.Logger) ([]string, error) {
	excludeSet := make(map[string]bool, len(exclude))
	for _, d := range exclude {
		if d = strings.TrimSpace(d); d != "" {
			excludeSet[strings.ToLower(d)] = true
		}
	}
	pathPrefixes := resolveExcludePaths(rootPath, excludePaths)

	var files []string
	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if path == rootPath {
				return err
			}
			if logger != nil {
				logger.Warn("walk: skipping unreadable path", "path", path, "error", err)
			}
			if info != nil && info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			if excludeSet[strings.ToLower(info.Name())] || isUnderAny(path, pathPrefixes) {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".c" || ext == ".h" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// resolveExcludePaths normalizes configured exclude paths against the scan
// target: relative entries are joined to rootPath, absolute entries are used
// as-is, and empty/whitespace entries are dropped. The result is a list of
// clean absolute directory prefixes.
func resolveExcludePaths(rootPath string, paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(rootPath, p)
		}
		out = append(out, filepath.Clean(p))
	}
	return out
}

// isUnderAny reports whether path is one of dirs or a descendant of any of them.
func isUnderAny(path string, dirs []string) bool {
	for _, dir := range dirs {
		if path == dir {
			return true
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			// filepath.Rel fails when the paths live on different volumes or mix
			// separators. Fall back to a lexical prefix check rather than
			// failing open on an unusual path form.
			if strings.HasPrefix(path, dir+string(filepath.Separator)) {
				return true
			}
			continue
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return true
		}
	}
	return false
}
