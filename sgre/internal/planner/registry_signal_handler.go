package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:              "signal-handler",
		CWE:               "CWE-479",
		SeedEventType:     "SIGNAL_HANDLER",
		EvidenceType:      "SIGNAL_HANDLER",
		DefaultSuspicion:  "confirmed",
		FilterChain:       "default",
		FilterFactories:    chainDefault(),
		BuildVerdictFacts: buildSignalHandlerVerdictFacts,
		// A signal handler that DIRECTLY calls a known non-async-signal-safe libc
		// function (malloc, printf, pthread_mutex_lock, ...) is a certain CWE-479
		// defect: the POSIX async-signal-safe list is fixed and authoritative, so
		// the detector needs no taint or flow proof — "confirmed" is sound here.
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "signal_handler_unsafe", Role: "sink", Detail: fmt.Sprintf("signal handler %s calls non-async-signal-safe %s() at line %d", c.FunctionName, c.VariableName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})
}
