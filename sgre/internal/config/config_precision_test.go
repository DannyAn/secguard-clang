package config

import "testing"

func TestPrecisionTierMode(t *testing.T) {
	t.Cleanup(func() { SetPrecisionTierOverride("") })

	c := &Config{}
	if got := c.PrecisionTierMode(); got != "balanced" {
		t.Fatalf("default = %q, want balanced (pre-dismiss non-proving tiers in complete-program scans)", got)
	}
	c.Scan.PrecisionTier = "off"
	if got := c.PrecisionTierMode(); got != "off" {
		t.Fatalf("explicit off = %q, want off (recall-maximal opt-out)", got)
	}
	c.Scan.PrecisionTier = "STRICT"
	if got := c.PrecisionTierMode(); got != "strict" {
		t.Fatalf("strict = %q", got)
	}
	c.Scan.PrecisionTier = "bogus"
	if got := c.PrecisionTierMode(); got != "balanced" {
		t.Fatalf("invalid = %q, want balanced (safe default)", got)
	}
	SetPrecisionTierOverride("off")
	if got := c.PrecisionTierMode(); got != "off" {
		t.Fatalf("override = %q, want off", got)
	}
	SetPrecisionTierOverride("")
	c.Scan.PrecisionTier = ""
	if got := c.PrecisionTierMode(); got != "balanced" {
		t.Fatalf("cleared override = %q, want balanced", got)
	}
}
