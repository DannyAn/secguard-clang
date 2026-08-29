// Package git shells out to the system git binary to compute a commit-range
// diff (changed files + added line numbers) for incremental review. It avoids a
// heavyweight go-git dependency: the binary is already cross-platform, and any
// user who can run `git diff` has git on PATH.
package git

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Diff is the changed-file set between base and head, plus the added-line
// numbers (new-side, 1-based) per file. It is the input to incremental review.
type Diff struct {
	Base  string
	Head  string
	Files []FileDiff
}

// FileDiff is one changed file in the diff.
type FileDiff struct {
	Path    string // post-change path, repo-relative, slash-separated
	OldPath string // pre-change path for renames, else empty
	Status  string // A (added) / M (modified) / D (deleted) / R (renamed)
	Lines   []int  // added-line numbers on the new side (1-based); empty for D
}

var hunkHeaderRe = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

// IsRepo reports whether repoDir is inside a git working tree.
func IsRepo(repoDir string) bool {
	return exec.Command("git", "-C", repoDir, "rev-parse", "--git-dir").Run() == nil
}

// RevParse resolves a ref (e.g. "HEAD", "HEAD~1", "origin/main") to a full SHA.
func RevParse(repoDir, ref string) (string, error) {
	out, err := run(repoDir, "rev-parse", ref)
	if err != nil {
		return "", fmt.Errorf("git: rev-parse %s: %w", ref, err)
	}
	return strings.TrimSpace(out), nil
}

// MergeBase returns the merge-base commit of a and b.
func MergeBase(repoDir, a, b string) (string, error) {
	out, err := run(repoDir, "merge-base", a, b)
	if err != nil {
		return "", fmt.Errorf("git: merge-base %s %s: %w", a, b, err)
	}
	return strings.TrimSpace(out), nil
}

// ComputeDiff computes the diff base..head restricted to C/H files. Added-line
// numbers are parsed from a unified diff with zero context lines (-U0), which is
// the compact form that still carries exact hunk positions.
func ComputeDiff(repoDir, base, head string) (*Diff, error) {
	out, err := run(repoDir, "diff", "-M", "-U0", base+".."+head, "--", "*.c", "*.h")
	if err != nil {
		return nil, fmt.Errorf("git: diff %s..%s: %w", base, head, err)
	}
	d := &Diff{Base: base, Head: head}
	d.parseUnifiedDiff(out)
	return d, nil
}

func (d *Diff) parseUnifiedDiff(text string) {
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var cur *FileDiff
	flush := func() {
		if cur != nil {
			d.Files = append(d.Files, *cur)
			cur = nil
		}
	}

	var newStart int
	var newLine int
	inHunk := false

	for sc.Scan() {
		line := sc.Text()

		switch {
		case strings.HasPrefix(line, "diff --git "):
			flush()
			rest := strings.TrimPrefix(line, "diff --git ")
			// rest is `a/<path> b/<path>`; paths are prefixed a/ and b/.
			a, b := splitDiffPaths(rest)
			cur = &FileDiff{
				OldPath: strings.TrimPrefix(a, "a/"),
				Path:    strings.TrimPrefix(b, "b/"),
				Status:  "M",
			}
			inHunk = false
		case strings.HasPrefix(line, "new file mode"):
			if cur != nil {
				cur.Status = "A"
			}
		case strings.HasPrefix(line, "deleted file mode"):
			if cur != nil {
				cur.Status = "D"
			}
		case strings.HasPrefix(line, "rename from "):
			if cur != nil {
				cur.OldPath = strings.TrimPrefix(line, "rename from ")
				cur.Status = "R"
			}
		case strings.HasPrefix(line, "rename to "):
			if cur != nil {
				cur.Path = strings.TrimPrefix(line, "rename to ")
			}
		case hunkHeaderRe.MatchString(line):
			m := hunkHeaderRe.FindStringSubmatch(line)
			newStart, _ = strconv.Atoi(m[3])
			newLine = newStart
			inHunk = true
		case inHunk && strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			if cur != nil {
				cur.Lines = append(cur.Lines, newLine)
			}
			newLine++
		case inHunk && strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---"):
			// removed line: does not advance the new-side line counter
		case inHunk && strings.HasPrefix(line, " "):
			newLine++
		case inHunk && line == `\ No newline at end of file`:
			// ignore
		}
	}
	flush()
}

// splitDiffPaths splits `a/<path> b/<path>` into the two path components. Paths
// are assumed free of spaces; C project paths almost always are, and a path
// with spaces is a rare edge case the first version does not need to handle.
func splitDiffPaths(rest string) (string, string) {
	idx := strings.Index(rest, " b/")
	if idx < 0 {
		return rest, rest
	}
	return rest[:idx], rest[idx+1:]
}

func run(repoDir string, args ...string) (string, error) {
	full := append([]string{"-C", repoDir}, args...)
	cmd := exec.Command("git", full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return "", fmt.Errorf("%s", msg)
		}
		return "", err
	}
	return stdout.String(), nil
}
