package indexer

import (
	"os"
	"path/filepath"
	"strings"
)

// DefaultExcludeDirs are the directory basenames skipped by default when no
// explicit --exclude is given. They are vendored third-party / build / test /
// fuzzing directories whose contents are not the audited project's own
// production code — scanning them floods the convergence pipeline with noise
// (redis's deps/ + tests/ produced the bulk of null-deref/uninit candidates).
var DefaultExcludeDirs = []string{
	"deps", "third_party", "third-party", "vendor", "external", "node_modules",
	"tests", "test", "fuzzing",
}

// WalkCFiles walks rootPath and returns every .c/.h file, skipping any
// directory whose basename is in exclude (case-insensitive). A skipped
// directory is pruned entirely via filepath.SkipDir.
func WalkCFiles(rootPath string, exclude []string) ([]string, error) {
	excludeSet := make(map[string]bool, len(exclude))
	for _, d := range exclude {
		if d = strings.TrimSpace(d); d != "" {
			excludeSet[strings.ToLower(d)] = true
		}
	}

	var files []string
	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if excludeSet[strings.ToLower(info.Name())] {
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
