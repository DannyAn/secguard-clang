package apikb

import "testing"

func TestArgumentInjectionSinks(t *testing.T) {
	for name, idx := range ArgumentInjectionSinks {
		if got, ok := ArgumentInjectionArgvIdx(name); !ok || got != idx {
			t.Errorf("ArgumentInjectionArgvIdx(%q) = (%d, %v), want (%d, true)", name, got, ok, idx)
		}
		if !IsArgumentInjectionSink(name) {
			t.Errorf("IsArgumentInjectionSink(%q) = false, want true", name)
		}
	}
	if IsArgumentInjectionSink("system") {
		t.Errorf("IsArgumentInjectionSink(\"system\") = true, want false (system is CWE-78)")
	}
	got, ok := ArgumentInjectionArgvIdx("execve")
	if !ok || got != 1 {
		t.Errorf("ArgumentInjectionArgvIdx(\"execve\") = (%d, %v), want (1, true)", got, ok)
	}
	got, ok = ArgumentInjectionArgvIdx("posix_spawn")
	if !ok || got != 4 {
		t.Errorf("ArgumentInjectionArgvIdx(\"posix_spawn\") = (%d, %v), want (4, true)", got, ok)
	}
}

func TestXMLInjectionSinks(t *testing.T) {
	for name, spec := range XMLInjectionSinks {
		got, ok := XMLInjectionSinkSpecByName(name)
		if !ok {
			t.Errorf("XMLInjectionSinkSpecByName(%q) = false, want true", name)
		}
		if got.TaintArgIdx != spec.TaintArgIdx || got.Category != spec.Category {
			t.Errorf("XMLInjectionSinkSpecByName(%q) = (%+v), want (%+v)", name, got, spec)
		}
		if !IsXMLInjectionSink(name) {
			t.Errorf("IsXMLInjectionSink(%q) = false, want true", name)
		}
	}
	if IsXMLInjectionSink("system") {
		t.Errorf("IsXMLInjectionSink(\"system\") = true, want false")
	}
	spec, ok := XMLInjectionSinkSpecByName("xmlXPathEvalExpression")
	if !ok || spec.TaintArgIdx != 1 || spec.Category != "xml_xpath_injection" {
		t.Errorf("xmlXPathEvalExpression spec = (%+v, %v), want (TaintArgIdx=1, Category=xml_xpath_injection)", spec, ok)
	}
	spec, ok = XMLInjectionSinkSpecByName("xmlSAXParseDoc")
	if !ok || spec.TaintArgIdx != 1 || spec.Category != "xml_injection" {
		t.Errorf("xmlSAXParseDoc spec = (%+v, %v), want (TaintArgIdx=1, Category=xml_injection)", spec, ok)
	}
}

func TestCRLFSinkCandidates(t *testing.T) {
	for name := range CRLFSinkCandidates {
		if !IsCRLFSinkCandidate(name) {
			t.Errorf("IsCRLFSinkCandidate(%q) = false, want true", name)
		}
	}
	if IsCRLFSinkCandidate("syslog") {
		t.Errorf("IsCRLFSinkCandidate(\"syslog\") = true, want false")
	}
}

func TestLogSinks(t *testing.T) {
	for name := range LogSinks {
		if !IsLogSink(name) {
			t.Errorf("IsLogSink(%q) = false, want true", name)
		}
	}
	if IsLogSink("fprintf") {
		t.Errorf("IsLogSink(\"fprintf\") = true, want false (fprintf needs heuristic)")
	}
}

func TestLogSinkCandidates(t *testing.T) {
	for name := range LogSinkCandidates {
		if !IsLogSinkCandidate(name) {
			t.Errorf("IsLogSinkCandidate(%q) = false, want true", name)
		}
	}
	if IsLogSinkCandidate("syslog") {
		t.Errorf("IsLogSinkCandidate(\"syslog\") = true, want false (syslog is unconditional LogSink)")
	}
}

func TestSanitizers(t *testing.T) {
	for name := range ArgumentSanitizers {
		if !IsArgumentSanitizer(name) {
			t.Errorf("IsArgumentSanitizer(%q) = false, want true", name)
		}
	}
	for name := range XMLSanitizers {
		if !IsXMLSanitizer(name) {
			t.Errorf("IsXMLSanitizer(%q) = false, want true", name)
		}
	}
	for name := range CRLFSanitizers {
		if !IsCRLFSanitizer(name) {
			t.Errorf("IsCRLFSanitizer(%q) = false, want true", name)
		}
	}
	for name := range LogSanitizers {
		if !IsLogSanitizer(name) {
			t.Errorf("IsLogSanitizer(%q) = false, want true", name)
		}
	}
	if IsArgumentSanitizer("system") {
		t.Errorf("IsArgumentSanitizer(\"system\") = true, want false")
	}
}

func TestSafeWrappersExtended(t *testing.T) {
	newWrappers := []string{
		"SafeExecArg", "validate_exec_arg", "sanitize_argv",
		"strip_crlf", "escape_crlf", "validate_header", "sanitize_header_value",
		"escape_newlines", "strip_newlines", "validate_log", "sanitize_log_message",
	}
	for _, name := range newWrappers {
		if !IsSafeWrapper(name) {
			t.Errorf("IsSafeWrapper(%q) = false, want true", name)
		}
	}
}
