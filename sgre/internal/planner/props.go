package planner

import "encoding/json"

// eventProps is the unified, typed view of the free-form JSON stored in
// security_events.properties. Detectors emit a loose subset of these keys;
// the planner reads them through this single struct so the field names live
// in one place instead of being re-declared per filter.
type eventProps struct {
	Variable    string `json:"variable"`
	Expression  string `json:"expression"`
	Function    string `json:"function"`
	Category    string `json:"category"`
	NonNullable string `json:"non_nullable"`
	IsTypeExpr  string `json:"is_type_expr"`
	Condition   string `json:"condition"`
	ScopeStart  int    `json:"scope_start"`
	ScopeEnd    int    `json:"scope_end"`
	Strength    string `json:"strength"`
	FreeLine    int    `json:"free_line"`
	UseLine     int    `json:"use_line"`
	Origin      string `json:"origin"`
	DeclLine    int    `json:"decl_line"`
	Definite    string `json:"definite"` // "true" for an explicit null assignment
	Callee      string `json:"callee"`
	API         string `json:"api"` // hardcoded_secret RegSetValueEx branch
	Name        string `json:"name"`
	Value       string `json:"value"`
	MutexA      string `json:"mutex_a"`
	MutexB      string `json:"mutex_b"`
	ReverseFunc string `json:"reverse_function"`
	Array       string `json:"array"`
	Index       string `json:"index"`
	KeySize     int    `json:"key_size"`
	Reason      string `json:"reason"`
	CheckFunc   string `json:"check_function"`
	UseFunc     string `json:"use_function"`
	PathArg     string `json:"path_arg"`
	Path        string `json:"path"`       // path-traversal sink argument text
	FormatArg   string `json:"format_arg"` // format-string sink argument text
	Mutex       string `json:"mutex"`
	LockLine    int    `json:"lock_line"`
	UnlockLine  int    `json:"unlock_line"`
	Divisor     string `json:"divisor"` // divide-by-zero divisor expression
	// ThreadFunctions is the comma-separated list of pthread thread function
	// names a shared_data_race event reports (race-condition detector).
	ThreadFunctions string `json:"thread_functions"`
}

func parseEventProps(raw string) eventProps {
	var p eventProps
	_ = json.Unmarshal([]byte(raw), &p)
	return p
}
