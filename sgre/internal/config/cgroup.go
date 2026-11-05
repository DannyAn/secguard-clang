package config

import (
	"os"
	"strconv"
	"strings"
)

// cgroup v2 and v1 memory-limit files. v2 is preferred; v1 is the fallback for
// hosts that still mount the legacy controller hierarchy.
const (
	cgroupV2MemoryMax   = "/sys/fs/cgroup/memory.max"
	cgroupV1MemoryLimit = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
)

// DetectCgroupMemoryLimit returns the cgroup memory ceiling in bytes, or 0 when
// no finite limit is set (a missing file, the "max" sentinel, an unreadable
// path, or a non-Linux host). cgroup v2 is checked first, then v1.
//
// The pipeline uses this to derive a Go soft memory limit and backpressure
// watermarks when the user has not configured them, so a containerized scan
// degrades to "GC pressure + throttled concurrency" instead of a cgroup OOM
// kill (exit 137).
func DetectCgroupMemoryLimit() int64 {
	if v, ok := readCgroupLimit(cgroupV2MemoryMax); ok {
		return v
	}
	if v, ok := readCgroupLimit(cgroupV1MemoryLimit); ok {
		return v
	}
	return 0
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
	if v >= (1<<63)-4096 {
		return 0, false
	}
	return v, true
}
