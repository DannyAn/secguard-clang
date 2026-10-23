//go:build !nosqlite

package evidence

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
)

// NE-06: a platform entry point (WinMain / wWinMain / DllMain / app_main)
// marks the scan tree as a complete program just like main does. Recognizing
// only main flips every Windows-DLL / firmware / library project into the
// boundary-scan fail-open mode and floods every boundary pointer parameter
// with a phantom seed.
func TestScanHasEntryPointPlatformEntries(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want bool
	}{
		{"main", "int main(void) { return 0; }", true},
		{"WinMain", "int WinMain(void *h, void *p, char *c, int n) { return 0; }", true},
		{"wWinMain", "int wWinMain(void *h, void *p, wchar_t *c, int n) { return 0; }", true},
		{"DllMain", "int DllMain(void *h, unsigned long r, void *p) { return 1; }", true},
		{"app_main", "void app_main(void) {}", true},
		{"no entry", "int helper(void) { return 0; }", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := db.NewTestStore(t)
			logger := log.Default()

			dir := t.TempDir()
			path := filepath.Join(dir, "entry.c")
			if err := os.WriteFile(path, []byte(tc.src), 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := indexer.NewIndexer(store, logger).Index(ctx, path); err != nil {
				t.Fatalf("index: %v", err)
			}
			if got := scanHasEntryPoint(ctx, store); got != tc.want {
				t.Errorf("scanHasEntryPoint(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}
