//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// The production out-of-bounds miss: the struct (with its member array) is
// declared in a header OUTSIDE the scan target. `secguard scan maf/src` — a
// subtree inside a git worktree — must still resolve the struct layout and the
// capacity macro from a sibling header (maf/include), or the unchecked-index
// channel silently drops `svr[actived_index]`.
func TestUncheckedIndexHeaderOutsideTarget(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	// The enclosing git worktree marker.
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	headerDir := filepath.Join(dir, "include")
	if err := os.MkdirAll(headerDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(headerDir, "maf_rbl_profile.h"), []byte(`#define MAF_RBL_COUNT 6

struct maf_rbl_svr_cfg {
    const char *domain;
    unsigned int action;
    unsigned int reply_code_any;
};

struct maf_rbl_profile {
    unsigned int actived_index;
    const char *actived_svr_name;
    struct maf_rbl_svr_cfg svr[MAF_RBL_COUNT];
};
`), 0644); err != nil {
		t.Fatal(err)
	}

	srcDir := filepath.Join(dir, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "maf_cli_dataplane_config.c"), []byte(`#include "maf_rbl_profile.h"

int maf_show_dataplane_config_active_rbl_server(struct maf_rbl_profile *rbl_profile, char *outbuf, int buflen, int *pos)
{
    int ret = maf_write_to_buffer(outbuf, buflen, pos, "%s",
        rbl_profile->svr[rbl_profile->actived_index].domain);
    if (ret != 0) {
        return ret;
    }
    return maf_show_dataplane_config_all_reply_code(&rbl_profile->svr[rbl_profile->actived_index], outbuf, buflen, pos);
}
`), 0644); err != nil {
		t.Fatal(err)
	}

	// Index ONLY the subtree, as `secguard scan maf/src` does.
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, srcDir); err != nil {
		t.Fatalf("index src: %v", err)
	}
	if _, err := NewBufferOverflowDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatal(err)
	}

	events, err := store.ListEventsByType(ctx, "BUFFER_ACCESS")
	if err != nil {
		t.Fatal(err)
	}
	type props struct {
		Category       string `json:"category"`
		Array          string `json:"array"`
		IndexSource    string `json:"index_source"`
		CapacitySymbol string `json:"capacity_symbol"`
		Size           string `json:"size"`
		ElemField      string `json:"elem_field"`
		Escape         string `json:"escape"`
	}
	var found *props
	for _, e := range events {
		var pr props
		if err := json.Unmarshal([]byte(e.Properties), &pr); err != nil {
			t.Fatalf("unmarshal props %q: %v", e.Properties, err)
		}
		if pr.Category == "array_oob_read_unchecked" && pr.Array == "rbl_profile->svr" {
			found = &pr
			break
		}
	}
	if found == nil {
		t.Fatalf("header outside the scan target produced ZERO unchecked-index events — the boundary-scan declaration gap is not fixed")
	}
	if found.IndexSource != "actived_index" {
		t.Errorf("index_source = %s, want actived_index", found.IndexSource)
	}
	if found.Size != "6" {
		t.Errorf("size = %s, want 6 (capacity macro from the worktree header)", found.Size)
	}
	if found.CapacitySymbol != "MAF_RBL_COUNT" {
		t.Errorf("capacity_symbol = %s, want MAF_RBL_COUNT", found.CapacitySymbol)
	}
	if found.ElemField != "domain" {
		t.Errorf("elem_field = %s, want domain", found.ElemField)
	}
	if found.Escape != "maf_show_dataplane_config_all_reply_code" {
		t.Errorf("escape = %s, want maf_show_dataplane_config_all_reply_code", found.Escape)
	}
}
