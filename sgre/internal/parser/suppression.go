package parser

import (
	"regexp"
	"strings"
)

// SuppressionDirective is one parsed in-source suppression comment (GAP-11).
type SuppressionDirective struct {
	// NextLine is true for `secguard-disable-next-line:` (suppress the following
	// line) and false for `secguard-disable-line:` (suppress this same line).
	NextLine bool
	// Types is the kebab-case vuln-type list (a single "all" is the wildcard).
	Types []string
	// Reason is the optional `reason=...` annotation.
	Reason string
}

var suppressionRe = regexp.MustCompile(`(?i)\bsecguard-disable-(next-line|line)\s*:\s*([a-z0-9-]+(?:\s*,\s*[a-z0-9-]+)*)(?:\s+reason=(.*))?`)

// ParseSuppressionComment parses a comment node's text into a suppression
// directive. It strips the `//` / `/*` … `*/` delimiters, so the same parser
// serves line and block comments. Returns ok=false when the comment is not a
// suppression directive.
func ParseSuppressionComment(commentText string) (SuppressionDirective, bool) {
	t := stripCommentDelims(commentText)
	m := suppressionRe.FindStringSubmatch(t)
	if m == nil {
		return SuppressionDirective{}, false
	}
	types := strings.FieldsFunc(m[2], func(r rune) bool { return r == ',' })
	for i := range types {
		types[i] = strings.TrimSpace(types[i])
	}
	reason := strings.TrimSpace(m[3])
	// Drop a trailing quote the regex may have captured on a block comment.
	reason = strings.TrimSpace(strings.TrimSuffix(reason, `*/`))
	return SuppressionDirective{
		NextLine: strings.EqualFold(m[1], "next-line"),
		Types:    types,
		Reason:   reason,
	}, true
}

func stripCommentDelims(text string) string {
	t := strings.TrimSpace(text)
	t = strings.TrimPrefix(t, "/*")
	t = strings.TrimSuffix(t, "*/")
	t = strings.TrimPrefix(t, "//")
	return strings.TrimSpace(t)
}
