//go:build !nosqlite

package planner

import (
	"testing"
)

// TestNullDeref_CallbackRegistrationSuppressesUnguardedEntry verifies that a
// function whose only reference is a function-pointer registration (ADDR_TAKEN
// edge) does NOT produce a "caller-arg / unguarded external entry" candidate
// for its parameter dereference. The parameter's nullability is bound to the
// registration-site context, not to an open direct-call chain, so failing open
// as a suspected candidate wastes an AI verdict on a framework idiom.
//
// This is the P1 pattern from the nlog production scan (88/206 candidates):
//
//	typedef void (*cb_t)(widget_t *w, int id);
//	void register_cb(cb_t f, const void *ctx, size_t sz, int type);
//	void send_widget(widget_t *w, int id) { printf("%u", w->seq); }
//	void init(void) { widget_t *w = make_widget(); if (w == NULL) return;
//	                  register_cb((cb_t)send_widget, w, sizeof(*w), 1); }
func TestNullDeref_CallbackRegistrationSuppressesUnguardedEntry(t *testing.T) {
	src := `typedef struct { unsigned int seq; } widget_t;
typedef void (*cb_t)(widget_t *w, int id);

extern void register_cb(cb_t f, const void *ctx, unsigned long sz, int type);
extern widget_t *make_widget(void);

void send_widget(widget_t *w, int id)
{
    unsigned int v = w->seq;
    (void)v;
}

void init(void)
{
    widget_t *w = make_widget();
    if (w == 0) return;
    register_cb((cb_t)send_widget, w, sizeof(*w), 1);
}
`
	res := planNullDerefFullSrc(t, src)
	for _, c := range res.Candidates {
		if c.Target.Variable == "w" && c.Target.Function == "send_widget" {
			t.Errorf("callback-registered function send_widget: expected NO candidate for w (suppressed by ADDR_TAKEN), got tier=%s",
				c.NullOriginTier)
		}
	}
}

// TestNullDeref_NonCallbackZeroCallSiteKeepsCandidate verifies that a
// zero-call-site externally-callable function WITHOUT an ADDR_TAKEN edge still
// produces the boundary fail-open candidate. The callback suppression must not
// over-suppress ordinary exported API functions.
func TestNullDeref_NonCallbackZeroCallSiteKeepsCandidate(t *testing.T) {
	src := `typedef struct { unsigned int seq; } widget_t;

unsigned int hash_widget(const widget_t *w)
{
    return w->seq;
}
`
	res := planNullDerefFullSrc(t, src)
	found := false
	for _, c := range res.Candidates {
		if c.Target.Variable == "w" {
			found = true
			if c.NullOriginTier != "caller-arg" {
				t.Errorf("non-callback zero-call-site: tier=%q, want caller-arg", c.NullOriginTier)
			}
		}
	}
	if !found {
		t.Errorf("non-callback zero-call-site: expected a candidate for w, got none")
	}
}

// TestNullDeref_ChainDedupFoldsForwardingChain verifies that a forwarding chain
// (send → body → tail, all dereferencing the same unguarded parameter `ips`)
// is folded into ONE candidate with ChainFunctions listing the folded functions,
// not 3 separate candidates. This is the P2 pattern from the nlog production
// scan (91/206 candidates).
func TestNullDeref_ChainDedupFoldsForwardingChain(t *testing.T) {
	src := `typedef struct { unsigned int attack_id; unsigned int event_num; } ips_log_t;
typedef struct { int dummy; } dataflow_ctx_t;

extern dataflow_ctx_t *dataflow_new(unsigned int v);

void write_ips_tail(dataflow_ctx_t *df, const ips_log_t *ips)
{
    unsigned int v = ips->attack_id;
    (void)v;
}

void write_ips_body(dataflow_ctx_t *df, const ips_log_t *ips)
{
    unsigned int v = ips->event_num;
    (void)v;
    write_ips_tail(df, ips);
}

void send_ips(ips_log_t *ips, unsigned int log_id)
{
    unsigned int v = ips->attack_id;
    (void)v;
    dataflow_ctx_t *df = dataflow_new(v);
    write_ips_body(df, ips);
}
`
	res := planNullDerefFullSrc(t, src)
	var ipsCandidates []EvidenceItem
	for _, c := range res.Candidates {
		if c.Target.Variable == "ips" {
			ipsCandidates = append(ipsCandidates, c)
		}
	}
	if len(ipsCandidates) == 0 {
		t.Fatalf("expected at least one ips candidate, got none")
	}
	if len(ipsCandidates) > 1 {
		var fns []string
		for _, c := range ipsCandidates {
			fns = append(fns, c.Target.Function)
		}
		t.Errorf("forwarding chain: expected 1 folded ips candidate, got %d (%v)", len(ipsCandidates), fns)
	}
}

// TestNullDeref_DefiniteNullNotFoldedOrSuppressed verifies that a definite-null
// candidate (variable assigned NULL then dereferenced) is neither suppressed by
// callback registration nor folded by chain-dedup. This is the true-positive
// form (use case C from the production report) that must survive all
// suppression/folding changes.
func TestNullDeref_DefiniteNullNotFoldedOrSuppressed(t *testing.T) {
	src := `#include <stddef.h>
typedef struct { unsigned int req_id; } dns_item_t;

void dns_callback(void *p)
{
    dns_item_t *item = NULL;
    unsigned int v = item->req_id;
    (void)v;
}
`
	res := planNullDerefFullSrc(t, src)
	found := false
	for _, c := range res.Candidates {
		if c.Target.Variable == "item" {
			found = true
			if !c.HasDefiniteNull {
				t.Errorf("definite-null candidate: HasDefiniteNull=false, want true")
			}
			if c.NullOriginTier != "cfg-proof" {
				t.Errorf("definite-null candidate: tier=%q, want cfg-proof", c.NullOriginTier)
			}
		}
	}
	if !found {
		t.Errorf("definite-null true positive: expected a candidate for item, got none")
	}
}
