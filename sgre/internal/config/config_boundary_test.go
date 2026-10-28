package config

import "testing"

func TestBoundaryAutoDismissMode(t *testing.T) {
	t.Cleanup(func() { SetBoundaryAutoDismissOverride("") })

	c := &Config{}
	if got := c.BoundaryAutoDismissMode(); got != "off" {
		t.Fatalf("default = %q, want off (recall-safe)", got)
	}
	c.Scan.BoundaryAutoDismiss = "ALL"
	if got := c.BoundaryAutoDismissMode(); got != "all" {
		t.Fatalf("all = %q", got)
	}
	c.Scan.BoundaryAutoDismiss = "bogus"
	if got := c.BoundaryAutoDismissMode(); got != "off" {
		t.Fatalf("invalid = %q, want off", got)
	}
	SetBoundaryAutoDismissOverride("external")
	if got := c.BoundaryAutoDismissMode(); got != "external" {
		t.Fatalf("CLI override = %q, want external", got)
	}
	SetBoundaryAutoDismissOverride("")
	if got := c.BoundaryAutoDismissMode(); got != "off" {
		t.Fatalf("cleared override = %q, want off", got)
	}
}
