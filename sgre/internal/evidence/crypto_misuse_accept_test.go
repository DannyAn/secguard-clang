//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/apikb"
)

// TestCryptoMisuse_AcceptedAlgorithm locks the crypto acceptance list
// (issue #289 T4): an algorithm registered in [crypto_misuse.accepted_algorithms]
// no longer surfaces a CRYPTO_MISUSE event, while an unlisted weak algorithm
// still does.
func TestCryptoMisuse_AcceptedAlgorithm(t *testing.T) {
	apikb.RegisterAcceptedCryptoAlgorithm("MD5", "non-security use: config checksum")
	store := runIndexAndDetect(t, "tc_crypto_accepted_algorithm.c")
	ctx := context.Background()

	events, err := store.ListEventsByType(ctx, "CRYPTO_MISUSE")
	if err != nil {
		t.Fatalf("list CRYPTO_MISUSE: %v", err)
	}
	seen := map[string]bool{}
	for _, e := range events {
		var props struct {
			Function string `json:"function"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		seen[props.Function] = true
	}
	if seen["MD5_Update"] {
		t.Errorf("MD5 is an accepted algorithm; MD5_Update must not emit a CRYPTO_MISUSE event")
	}
	if !seen["SHA1_Update"] {
		t.Errorf("SHA1 is an unlisted weak algorithm; SHA1_Update must still emit a CRYPTO_MISUSE event")
	}
}
