package planner

import (
	"fmt"
	"strconv"
)

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:             "loop-termination",
		CWE:              "CWE-835",
		SeedEventType:    "LOOP_TERMINATION",
		EvidenceType:     "LOOP_TERMINATION",
		DefaultSuspicion: "suspected",
		FilterFactories:  chainDefault(),
		// Every shape is a heuristic, never auto-confirmed: the pipeline cannot
		// rule out a pointer alias, an external thread/callback write, or a
		// function side-effect, so "no progress" is a lead the AI judges against
		// the code context — exactly the conservative split the issue's §5
		// demands for intentional infinite loops and event-driven loops.
		Categories: []string{"no_progress", "zero_step", "continue_bypass"},
		BuildVerdictFacts: func(c Candidate) []VerdictFact {
			return buildLoopTerminationVerdictFacts(c)
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "loop_progress", Role: "sink", Detail: loopProgressDetail(c)},
				{Type: "exit_condition", Role: "condition", Detail: fmt.Sprintf("the loop exit condition `%s` depends on `%s`", c.LoopCondition, c.VariableName)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
			return frags
		},
		ReviewAssumptions: []string{
			"The loop's exit-condition variable is a function-local scalar whose only possible writes are the direct assignments/updates the detector scanned",
			"A loop that never advances its exit variable, and has no break/return/goto alternative exit, runs forever once entered",
		},
		RequiredEvidence: []string{"loop exit condition", "progress variable", "the specific no-progress mechanism (missing write / no-op write / continue bypass)"},
		KnownLimitations: []string{
			"Conditional-branch bypass (the update runs on only one branch, without a continue) is not modelled yet — only the continue form is flagged",
			"A progress variable updated through a pointer alias or an unknown function is conservatively skipped (the pipeline cannot follow it)",
			"Wrong-direction updates (the update moves away from the exit condition) and overflow/wraparound of the counter are left to the AI",
		},
	})
}

func buildLoopTerminationVerdictFacts(c Candidate) []VerdictFact {
	facts := make([]VerdictFact, 0, 4)
	if c.LoopKind != "" {
		facts = append(facts, VerdictFact{Token: "loop-kind@" + c.LoopKind, Detail: fmt.Sprintf("the loop construct is %s", c.LoopKind)})
	}
	if c.LoopCondition != "" {
		facts = append(facts, VerdictFact{Token: "exit-cond@" + c.LoopCondition, Detail: fmt.Sprintf("the loop exit condition is `%s`", c.LoopCondition)})
	}
	if c.VariableName != "" {
		facts = append(facts, VerdictFact{Token: "progress@" + c.VariableName, Detail: fmt.Sprintf("`%s` is the exit-condition variable that must advance", c.VariableName)})
	}
	switch c.Category {
	case "no_progress":
		facts = append(facts, VerdictFact{Token: "no-write", Detail: "the progress variable is never assigned or updated in the loop body or update clause, and there is no break/return/goto alternative exit — if the loop is entered the condition never changes"})
	case "zero_step":
		facts = append(facts, VerdictFact{Token: "zero-step@" + lineStr(c.ProgressLine), Detail: fmt.Sprintf("the only write(s) to the progress variable are provable no-ops (the first at line %d), so the value cannot change", c.ProgressLine)})
	case "continue_bypass":
		facts = append(facts, VerdictFact{Token: "cont-bypass@" + lineStr(c.ProgressLine), Detail: fmt.Sprintf("a `continue` at line %d precedes every progress write, so that back-edge skips the update", c.ProgressLine)})
	}
	return facts
}

func loopProgressDetail(c Candidate) string {
	switch c.Category {
	case "no_progress":
		return fmt.Sprintf("a %s loop in %s at line %d never writes its exit-condition variable `%s` and has no break/return/goto exit", c.LoopKind, c.FunctionName, c.Line, c.VariableName)
	case "zero_step":
		return fmt.Sprintf("a %s loop in %s at line %d updates `%s` only with a no-op write (line %d)", c.LoopKind, c.FunctionName, c.Line, c.VariableName, c.ProgressLine)
	case "continue_bypass":
		return fmt.Sprintf("a %s loop in %s at line %d has a `continue` (line %d) that skips every write to `%s`", c.LoopKind, c.FunctionName, c.Line, c.ProgressLine, c.VariableName)
	}
	return fmt.Sprintf("a %s loop in %s at line %d fails to advance `%s`", c.LoopKind, c.FunctionName, c.Line, c.VariableName)
}

func lineStr(n int) string {
	if n <= 0 {
		return "0"
	}
	return strconv.Itoa(n)
}
