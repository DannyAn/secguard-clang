package planner

import "github.com/DannyAn/secguard-clang/internal/config"

// This file is the single source of truth for the type→severity scale
// (GAP-10, docs/GLM5.3能力缺口落地实施设计20261101.md §7). The scale is
// impact × exploitability: CRITICAL = write primitive / RCE / long-lived
// credential compromise; HIGH = local integrity/confidentiality loss / privilege
// escalation / high-value chain; MEDIUM = DoS / chain precondition /
// scenario-dependent; LOW = robustness / style. DoS classes never reach the top
// tier; write-primitive classes always do.
//
// RegisterVulnType fills a spec's empty DefaultSeverity/CategorySeverity from
// these tables, so the scale lives in ONE place instead of 28 registry files.

var defaultSeverityByType = map[string]string{
	// CRITICAL — write primitive / RCE / long-lived credential loss.
	"double-free":          "critical",
	"use-after-free":       "critical",
	"injection":            "critical",
	"hardcoded-secret":     "critical",
	"stack-address-escape": "critical",
	"invalid-free":         "critical",

	// HIGH — local integrity/confidentiality loss / privilege escalation.
	"buffer-overflow":       "high",
	"out-of-bounds":         "high",
	"format-string":         "high",
	"path-traversal":        "high",
	"race-condition":        "high",
	"crypto-misuse":         "high",
	"unbounded-length-copy": "high",

	// MEDIUM — DoS / chain precondition / scenario-dependent.
	"null-deref":          "medium",
	"divide-by-zero":      "medium",
	"integer-overflow":    "medium",
	"deadlock":            "medium",
	"signal-handler":      "medium",
	"sizeof-misuse":       "medium",
	"memory-leak":         "medium",
	"resource-leak":       "medium",
	"uninit":              "medium",
	"argument-type":       "medium",
	"dangerous-function":  "medium",
	"data-representation": "medium",
	"implicit-contract":   "medium",
	"signed-compare":      "medium",
	"switch-fallthrough":  "medium",

	// LOW — robustness / style.
	"unchecked-return": "low",
}

// categorySeverityByType overrides a type's default per event category, ONLY
// where the category's impact differs from the type default. Category names are
// the detector's actual event categories (not the §7.3 feature labels).
var categorySeverityByType = map[string]map[string]string{
	"injection": {
		"command_injection":   "critical",
		"sql_injection":       "high",
		"argument_injection":  "medium",
		"xml_xpath_injection": "medium",
		"xml_injection":       "low",
		"log_injection":       "low",
	},
	"buffer-overflow": {
		"heap_oob_write":   "critical",
		"layout_oob_write": "critical",
		"format_overflow":  "critical",
	},
	"race-condition": {
		"shared_data_race": "medium",
	},
	"integer-overflow": {
		"size_calc_overflow":      "high",
		"size_mul_const_overflow": "high",
	},
	"crypto-misuse": {
		"weak_algorithm": "medium",
		"weak_random":    "medium",
	},
	"path-traversal": {
		"world_writable_file": "medium",
		"world_writable_var":  "medium",
	},
}

// severityOverride returns the user's explicit [severity] config override for a
// (type, category) pair, or "" when none is set. It is consulted AFTER the
// per-category/default registry scale, so a user override wins over the built-in
// scale (a documented user decision, never asserted by the SKILL-frontmatter
// guard).
func severityOverride(vulnType, category string) string {
	ov := config.Load().SeverityOverrides()
	if len(ov) == 0 {
		return ""
	}
	if s := ov[vulnType+"."+category]; s != "" {
		return normalizeSeverityToken(s)
	}
	if s := ov[category]; s != "" {
		return normalizeSeverityToken(s)
	}
	if s := ov[vulnType]; s != "" {
		return normalizeSeverityToken(s)
	}
	return ""
}

// normalizeSeverityToken normalizes a config severity spelling to the canonical
// lowercase token the findings table accepts.
func normalizeSeverityToken(s string) string {
	switch s {
	case "critical", "crit":
		return "critical"
	case "high":
		return "high"
	case "medium", "med":
		return "medium"
	case "low":
		return "low"
	case "info":
		return "info"
	}
	return ""
}
