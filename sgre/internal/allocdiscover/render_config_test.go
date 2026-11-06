//go:build !nosqlite

package allocdiscover

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/config"
)

// A rendered suggestion must be loadable as a secguard.toml: the high/medium
// entries become the effective names lists, while "needs review" (low) entries
// stay commented out and never activate an unvetted allocator/deallocator.
func TestRenderRoundTripsThroughConfig(t *testing.T) {
	r := &Result{
		Allocators: []Entry{
			{Name: "myapp_malloc", Confidence: ConfHigh, Reasons: []string{"name pattern *_malloc"}},
			{Name: "buffer_create", Confidence: ConfLow, Reasons: []string{"signature heuristic only"}},
		},
		Deallocators: []Entry{
			{Name: "myapp_free", Confidence: ConfHigh, Reasons: []string{"name pattern *_free"}},
		},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "secguard.toml")
	if err := os.WriteFile(path, []byte(r.Render()), 0644); err != nil {
		t.Fatal(err)
	}
	config.SetExplicitPath(path)
	t.Cleanup(func() { config.SetExplicitPath("") })

	cfg, err := config.LoadE()
	if err != nil {
		t.Fatalf("rendered suggestion is not loadable: %v", err)
	}
	if got := cfg.AllocatorNames(); len(got) != 1 || got[0] != "myapp_malloc" {
		t.Errorf("allocators = %v, want [myapp_malloc] (low confidence must stay inactive)", got)
	}
	if got := cfg.DeallocatorNames(); len(got) != 1 || got[0] != "myapp_free" {
		t.Errorf("deallocators = %v, want [myapp_free]", got)
	}
}
