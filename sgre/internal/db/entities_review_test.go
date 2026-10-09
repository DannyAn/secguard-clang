package db

import "testing"

func TestEffectiveStatus_AutoConfirmReviewVerdicts(t *testing.T) {
	cases := []struct {
		reviewStatus string
		want         string
	}{
		{"", "confirmed"},                    // unreviewed auto-confirmed stands
		{"ai_confirmed", "confirmed"},        // AI agrees
		{"false_positive", "dismissed"},      // AI refutes → suppress
		{"needs_more_evidence", "confirmed"}, // inconclusive → conservative keep
	}
	for _, c := range cases {
		f := &Finding{Status: StatusAutoConfirmed, ReviewStatus: c.reviewStatus}
		if got := f.EffectiveStatus(); got != c.want {
			t.Errorf("EffectiveStatus(auto-confirmed, review=%q) = %q, want %q", c.reviewStatus, got, c.want)
		}
	}
}

func TestFinalStatus_AutoConfirmReviewVerdicts(t *testing.T) {
	cases := []struct {
		reviewStatus string
		want         string
	}{
		{"", "confirmed"},
		{"ai_confirmed", "confirmed"},
		{"false_positive", "dismissed"},
		{"needs_more_evidence", "confirmed"},
	}
	for _, c := range cases {
		f := &Finding{Status: StatusAutoConfirmed, ReviewStatus: c.reviewStatus}
		if got := f.FinalStatus(); got != c.want {
			t.Errorf("FinalStatus(auto-confirmed, review=%q) = %q, want %q", c.reviewStatus, got, c.want)
		}
	}
}

func TestEffectiveStatus_LegacyVerdictsUnchanged(t *testing.T) {
	cases := []struct {
		reviewStatus string
		firstPass    string
		want         string
	}{
		{"confirmed", StatusAutoConfirmed, "confirmed"},
		{"confirmed", "suspected", "confirmed"},
		{"dismissed", StatusAutoConfirmed, "dismissed"},
		{"dismissed", "suspected", "dismissed"},
		{"suspected-kept", StatusAutoConfirmed, "dismissed"},
		{"suspected-kept", "suspected", "dismissed"},
		{"", StatusAutoConfirmed, "confirmed"},
		{"", "suspected", "dismissed"},
	}
	for _, c := range cases {
		f := &Finding{Status: c.firstPass, ReviewStatus: c.reviewStatus}
		if got := f.EffectiveStatus(); got != c.want {
			t.Errorf("EffectiveStatus: ReviewStatus=%q Status=%q → %q, want %q", c.reviewStatus, c.firstPass, got, c.want)
		}
	}
}

func TestFinalStatus_LegacyVerdictsUnchanged(t *testing.T) {
	cases := []struct {
		reviewStatus string
		firstPass    string
		want         string
	}{
		{"confirmed", StatusAutoConfirmed, "confirmed"},
		{"confirmed", "suspected", "confirmed"},
		{"dismissed", StatusAutoConfirmed, "dismissed"},
		{"dismissed", "suspected", "dismissed"},
		{"suspected-kept", StatusAutoConfirmed, "dismissed"},
		{"suspected-kept", "suspected", "dismissed"},
		{"", StatusAutoConfirmed, "confirmed"},
		{"", "suspected", "dismissed"},
		{"", "dismissed", "dismissed"},
	}
	for _, c := range cases {
		f := &Finding{Status: c.firstPass, ReviewStatus: c.reviewStatus}
		if got := f.FinalStatus(); got != c.want {
			t.Errorf("FinalStatus: ReviewStatus=%q Status=%q → %q, want %q", c.reviewStatus, c.firstPass, got, c.want)
		}
	}
}
