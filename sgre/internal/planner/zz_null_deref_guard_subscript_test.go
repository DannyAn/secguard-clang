//go:build !nosqlite

package planner

import (
	"strings"
	"testing"
)

// Regression tests for the guard-name mismatch that leaked a false candidate per
// guarded subscript/member access, and for the evidence text that described a
// loop-carried source as if it preceded the use.

const subscriptGuardSrc = `#include <stdlib.h>

struct Packet { unsigned char *data; };
static struct Packet *packet_queue[16];
static int queue_size;

void cleanup_packets(void)
{
    for (int i = 0; i < queue_size; i++) {
        if (packet_queue[i]) {
            free(packet_queue[i]->data);
            free(packet_queue[i]);
            packet_queue[i] = NULL;
        }
    }
    queue_size = 0;
}
`

// TestNullDeref_SubscriptGuardCoversDereference: `if (packet_queue[i])` guards
// the dereference of `packet_queue[i]`. The null source at the end of the loop
// body (`packet_queue[i] = NULL`) is loop-carried into the next iteration, so
// without the guard the candidate is produced; with it the filter must drop it.
// This was a production false positive (the classifier had to dismiss it) because
// the guard was recorded as the base name `packet_queue` while the dereference
// and the source are both recorded as `packet_queue[i]`, and GuardFilter matches
// names exactly.
func TestNullDeref_SubscriptGuardCoversDereference(t *testing.T) {
	res := planNullDeref(t, subscriptGuardSrc)
	if c := candidateForFunc(t, res, "cleanup_packets"); c != nil {
		t.Errorf("cleanup_packets must NOT be flagged: if (packet_queue[i]) guards the dereference, got var=%s line=%d hint=%s", c.Target.Variable, c.Target.Line, c.Hint)
	}
}

// TestNullDeref_GuardDoesNotSuppressUnrelatedDeref is the counterpart: a guard
// scope must only suppress dereferences of the guarded expression itself.
func TestNullDeref_GuardDoesNotSuppressUnrelatedDeref(t *testing.T) {
	src := `#include <stdlib.h>

struct Packet { unsigned char *data; };
static struct Packet *packet_queue[16];

int unrelated(int i)
{
    if (packet_queue[i]) {
        struct Packet *q = NULL;
        q->data = 0; /* genuine: q is NULL, unrelated to the guard */
        return 1;
    }
    return 0;
}
`
	res := planNullDeref(t, src)
	if c := candidateForFunc(t, res, "unrelated"); c == nil {
		t.Errorf("the dereference of q must stay reported: the guard on packet_queue[i] says nothing about q")
	}
}

// TestNullDeref_LoopCarriedSourceEvidenceWording pins the evidence text for a
// source that textually FOLLOWS the use: it must not read "before the
// dereference", which is self-contradictory and cost the classifier reasoning
// turns in production.
func TestNullDeref_LoopCarriedSourceEvidenceWording(t *testing.T) {
	src := `#include <stdlib.h>

struct Packet { unsigned char *data; };
static struct Packet *packet_queue[16];
static int queue_size;

void drain(void)
{
    for (int i = 0; i < queue_size; i++) {
        free(packet_queue[i]->data);
        packet_queue[i] = NULL;
    }
}
`
	res := planNullDeref(t, src)
	c := candidateForFunc(t, res, "drain")
	if c == nil {
		t.Fatalf("drain must be flagged (the loop-carried NULL reaches the next iteration), got: %s", candidateNames(res))
	}
	for _, e := range c.Evidence {
		if e.Type != "nullable_source" {
			continue
		}
		if strings.Contains(e.Detail, "before the dereference") {
			t.Errorf("a loop-carried source must not be described as preceding the use, got: %s", e.Detail)
		}
		if !strings.Contains(e.Detail, "back-edge") {
			t.Errorf("a loop-carried source should name the back-edge, got: %s", e.Detail)
		}
		return
	}
	t.Errorf("expected a nullable_source evidence fragment, got %+v", c.Evidence)
}
