package config

import (
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// cgroup v2 and v1 memory-limit files. v2 is preferred; v1 is the fallback for
// hosts that still mount the legacy controller hierarchy.
const (
	cgroupV2MemoryMax   = "/sys/fs/cgroup/memory.max"
	cgroupV1MemoryLimit = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
)

// cgroupV1UnlimitedSentinel is the byte value cgroup v1 reports as "unlimited"
// (~2^63-1). A value at or above it means "no limit", not a real ceiling.
const cgroupV1UnlimitedSentinel = (1 << 63) - 4096

// DetectCgroupMemoryLimit returns the cgroup memory ceiling in bytes, or 0 when
// no finite limit is set (a missing file, the "max" sentinel, an unreadable
// path, or a non-Linux host). cgroup v2 is checked first, then v1.
//
// The limit is resolved at the PROCESS's cgroup path (from /proc/self/cgroup),
// walking every ancestor and taking the smallest finite ceiling, not just the
// fixed /sys/fs/cgroup root file. With Docker --cgroupns=host (and older
// containerd/k8s), the root file is "max" while the real limit lives under the
// container's cgroup path — reading only the root would silently disable the
// OOM protection. The fixed root paths remain as a last-resort fallback.
func DetectCgroupMemoryLimit() int64 {
	proc, _ := os.ReadFile("/proc/self/cgroup")
	v2Paths, v1Paths := cgroupMemoryLimitPaths(string(proc))
	if v := minCgroupLimit(v2Paths); v > 0 {
		return v
	}
	if v := minCgroupLimit(v1Paths); v > 0 {
		return v
	}
	return 0
}

// cgroupMemoryLimitPaths returns the candidate memory-limit files for the
// process's own cgroup hierarchy (v2 first, then v1), each ordered from the
// process's cgroup up to the hierarchy root. The fixed root paths are always
// included as fallbacks so a cgroupfs without /proc self-cgroup still works.
func cgroupMemoryLimitPaths(procSelfCgroup string) (v2, v1 []string) {
	v2 = []string{cgroupV2MemoryMax}
	v1 = []string{cgroupV1MemoryLimit}
	for _, line := range strings.Split(procSelfCgroup, "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) < 3 {
			continue
		}
		rel := fields[2]
		if !strings.HasPrefix(rel, "/") {
			continue
		}
		// path.Clean normalizes and confines the kernel-provided path; "/.."
		// must not escape the hierarchy root.
		rel = strings.TrimPrefix(path.Clean("/"+rel), "/")
		switch {
		case fields[0] == "0" && fields[1] == "":
			v2 = append(v2, cgroupAncestorPaths("/sys/fs/cgroup", rel, "memory.max")...)
		case strings.Contains(fields[1], "memory"):
			v1 = append(v1, cgroupAncestorPaths("/sys/fs/cgroup/memory", rel, "memory.limit_in_bytes")...)
		}
	}
	return v2, v1
}

// cgroupAncestorPaths returns <root>/<rel>/<file>, then each ancestor up to
// <root>/<file>. The effective memory limit is the smallest finite value on
// that chain.
func cgroupAncestorPaths(root, rel, file string) []string {
	dir := filepath.Clean(filepath.Join(root, rel))
	if !strings.HasPrefix(dir+string(filepath.Separator), filepath.Clean(root)+string(filepath.Separator)) {
		dir = root
	}
	var out []string
	for {
		out = append(out, filepath.Join(dir, file))
		rootClean := filepath.Clean(root)
		if filepath.Clean(dir) == rootClean {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return out
}

// minCgroupLimit returns the smallest finite limit among the candidate files,
// or 0 when none is finite.
func minCgroupLimit(paths []string) int64 {
	var min int64
	for _, p := range paths {
		v, ok := readCgroupLimit(p)
		if !ok {
			continue
		}
		if min == 0 || v < min {
			min = v
		}
	}
	return min
}

// readCgroupLimit parses one cgroup memory-limit file. It reports ok=false for
// "max", a missing/unreadable file, a non-numeric value, or the v1 "unlimited"
// sentinel near 2^63 — none of which represents a usable finite ceiling.
func readCgroupLimit(path string) (int64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(b))
	if s == "" || s == "max" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 {
		return 0, false
	}
	// cgroup v1 reports the unlimited ceiling as ~2^63-1 bytes. Treat that as
	// "no limit", not as an absurd soft cap that would force constant GC.
	if v >= cgroupV1UnlimitedSentinel {
		return 0, false
	}
	return v, true
}
