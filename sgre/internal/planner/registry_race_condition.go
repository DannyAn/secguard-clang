package planner

import "fmt"

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:             "race-condition",
		CWE:              "CWE-362",
		SeedEventType:    "RACE_CONDITION",
		EvidenceType:     "RACE_CONDITION",
		DefaultSuspicion: "suspected",
		FilterChain:      "race-condition",
		FilterFactories:    chainRaceCondition(),
		BuildVerdictFacts: buildRaceConditionVerdictFacts,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			if c.Category == "shared_data_race" {
				frags := []EvidenceFragment{
					{Type: "data_race", Role: "sink", Detail: fmt.Sprintf("unsynchronized shared-variable access to %s in %s at line %d", c.VariableName, c.FunctionName, c.Line)},
				}
				if c.ThreadFunctions != "" {
					frags = append(frags, EvidenceFragment{Type: "thread_functions", Role: "condition", Detail: fmt.Sprintf("accessed by thread functions: %s", c.ThreadFunctions)})
				}
				if c.ThreadInstances > 0 {
					frags = append(frags, EvidenceFragment{Type: "thread_instances", Role: "condition", Detail: fmt.Sprintf("%d distinct thread instances", c.ThreadInstances)})
				}
				if c.WriteLine > 0 {
					frags = append(frags, EvidenceFragment{Type: "write_line", Role: "source", Detail: fmt.Sprintf("conflicting write at line %d", c.WriteLine)})
				}
				frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
				return frags
			}
			if c.Category == "toctou_shared_state" {
				frags := []EvidenceFragment{
					{Type: "shared_state", Role: "sink", Detail: fmt.Sprintf("shared state written after its lock is released in %s at line %d", c.FunctionName, c.Line)},
				}
				if c.Mutex != "" {
					detail := fmt.Sprintf("state guarded by %s", c.Mutex)
					if c.LockLine > 0 && c.UnlockLine > 0 {
						detail = fmt.Sprintf("state guarded by %s (locked at line %d, unlocked at line %d)", c.Mutex, c.LockLine, c.UnlockLine)
					}
					frags = append(frags, EvidenceFragment{Type: "lock_scope", Role: "condition", Detail: detail})
				}
				frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
				return frags
			}
			frags := []EvidenceFragment{
				{Type: "toctou", Role: "sink", Detail: fmt.Sprintf("time-of-check-time-of-use in %s at line %d", c.FunctionName, c.Line)},
			}
			if c.CheckFunction != "" {
				frags = append(frags, EvidenceFragment{Type: "check_call", Role: "source", Detail: fmt.Sprintf("check call: %s", c.CheckFunction)})
			}
			if c.UseFunction != "" {
				frags = append(frags, EvidenceFragment{Type: "use_call", Role: "sink", Detail: fmt.Sprintf("use call: %s", c.UseFunction)})
			}
			if c.CheckPathArg != "" {
				frags = append(frags, EvidenceFragment{Type: "shared_arg", Role: "condition", Detail: fmt.Sprintf("argument checked then used: %s", c.CheckPathArg)})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
	})
}

func buildRaceConditionVerdictFacts(c Candidate) []VerdictFact {
	facts := make([]VerdictFact, 0, 4)
	if c.Category != "" {
		facts = append(facts, VerdictFact{
			Token:  "cat@" + c.Category,
			Detail: "detector category: " + c.Category + " (shared_global_write / toctou / lock_order / shared_access)",
		})
	}
	if c.ThreadFunctions != "" {
		facts = append(facts, VerdictFact{
			Token:  "threads@" + c.ThreadFunctions,
			Detail: "the thread functions that access the shared variable: " + c.ThreadFunctions,
		})
	}
	if c.Mutex != "" {
		facts = append(facts, VerdictFact{
			Token:  "mutex@" + c.Mutex,
			Detail: "the mutex guarding the critical section: " + c.Mutex,
		})
	}
	return facts
}
