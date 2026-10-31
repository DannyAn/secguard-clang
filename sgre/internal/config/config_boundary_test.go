package config

import "testing"

func TestBoundaryAutoDismissMode(t *testing.T) {
	t.Cleanup(func() { SetBoundaryAutoDismissOverride("") })

	c := &Config{}
	if got := c.BoundaryAutoDismissMode(); got != "external" {
		t.Fatalf("default = %q, want external (pre-dismiss fail-open assumptions)", got)
	}
	c.Scan.BoundaryAutoDismiss = "off"
	if got := c.BoundaryAutoDismissMode(); got != "off" {
		t.Fatalf("explicit off = %q, want off (recall-maximal opt-out)", got)
	}
	c.Scan.BoundaryAutoDismiss = "ALL"
	if got := c.BoundaryAutoDismissMode(); got != "all" {
		t.Fatalf("all = %q", got)
	}
	c.Scan.BoundaryAutoDismiss = "bogus"
	if got := c.BoundaryAutoDismissMode(); got != "external" {
		t.Fatalf("invalid = %q, want external (safe default)", got)
	}
	SetBoundaryAutoDismissOverride("external")
	if got := c.BoundaryAutoDismissMode(); got != "external" {
		t.Fatalf("CLI override = %q, want external", got)
	}
	SetBoundaryAutoDismissOverride("")
	if got := c.BoundaryAutoDismissMode(); got != "external" {
		t.Fatalf("cleared override = %q, want external", got)
	}
}
