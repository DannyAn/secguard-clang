package cli

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/DannyAn/secguard-clang/internal/log"
)

// MemoryMonitor tracks process memory usage and signals backpressure.
// It reads cgroup v2 memory.current (authoritative in production), falls back
// to /proc/self/status VmRSS (Linux without cgroup), then to
// runtime.ReadMemStats().HeapAlloc (macOS / development).
type MemoryMonitor struct {
	highBytes int64
	lowBytes  int64
	pressured atomic.Bool
	current   atomic.Int64
	stop      chan struct{}
}

// NewMemoryMonitor creates a monitor with the given high/low watermarks in
// bytes. A zero high watermark means backpressure is disabled (the monitor
// never signals pressure).
func NewMemoryMonitor(highBytes, lowBytes int64) *MemoryMonitor {
	return &MemoryMonitor{
		highBytes: highBytes,
		lowBytes:  lowBytes,
		stop:      make(chan struct{}),
	}
}

// Pressured reports whether the process is under memory pressure (current
// usage >= high watermark). The pipeline checks this before admitting new
// concurrent tasks; when true, concurrency drops to 1.
func (m *MemoryMonitor) Pressured() bool {
	if m == nil || m.highBytes == 0 {
		return false
	}
	return m.pressured.Load()
}

// Current returns the last sampled memory usage in bytes.
func (m *MemoryMonitor) Current() int64 {
	if m == nil {
		return 0
	}
	return m.current.Load()
}

// Start launches the monitor goroutine. It samples every interval until Stop.
func (m *MemoryMonitor) Start(interval time.Duration, logger *log.Logger) {
	if m == nil || m.highBytes == 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-m.stop:
				return
			case <-ticker.C:
				cur := readMemoryBytes()
				m.current.Store(cur)
				if !m.pressured.Load() && cur >= m.highBytes {
					m.pressured.Store(true)
					if logger != nil {
						logger.Warn("memory pressure: high watermark reached",
							"current_mb", cur/1024/1024,
							"high_mb", m.highBytes/1024/1024,
							"action", "reduce_concurrency")
					}
				} else if m.pressured.Load() && cur <= m.lowBytes {
					m.pressured.Store(false)
					if logger != nil {
						logger.Info("memory pressure: low watermark reached, restoring concurrency",
							"current_mb", cur/1024/1024,
							"low_mb", m.lowBytes/1024/1024)
					}
				}
			}
		}
	}()
}

// Stop terminates the monitor goroutine.
func (m *MemoryMonitor) Stop() {
	if m == nil || m.highBytes == 0 {
		return
	}
	close(m.stop)
}

// readMemoryBytes returns the current process memory usage in bytes.
// Priority: cgroup v2 memory.current → /proc/self/status VmRSS → HeapAlloc.
func readMemoryBytes() int64 {
	if v := readCgroupV2Memory(); v > 0 {
		return v
	}
	if v := readVmRSS(); v > 0 {
		return v
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return int64(ms.HeapAlloc)
}

// readCgroupV2Memory reads memory.current from the cgroup v2 hierarchy.
// Returns 0 if unavailable (macOS, cgroup v1, or no cgroup).
func readCgroupV2Memory() int64 {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return 0
	}
	var cgroupPath string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) < 3 {
			continue
		}
		if fields[1] == "" || strings.Contains(fields[1], "memory") {
			cgroupPath = fields[2]
			break
		}
	}
	if cgroupPath == "" {
		return 0
	}
	memFile := "/sys/fs/cgroup" + cgroupPath + "/memory.current"
	data, err = os.ReadFile(memFile)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// readVmRSS reads VmRSS from /proc/self/status. Returns 0 if unavailable.
func readVmRSS() int64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, err := strconv.ParseInt(fields[1], 10, 64)
				if err == nil {
					return v * 1024
				}
			}
		}
	}
	return 0
}
