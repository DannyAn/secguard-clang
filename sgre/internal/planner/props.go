package planner

import "encoding/json"

// eventProps is the unified, typed view of the free-form JSON stored in
// security_events.properties. Detectors emit a loose subset of these keys;
// the planner reads them through this single struct so the field names live
// in one place instead of being re-declared per filter.
type eventProps struct {
	Variable     string `json:"variable"`
	Expression   string `json:"expression"`
	Function     string `json:"function"`
	Category     string `json:"category"`
	NonNullable  string `json:"non_nullable"`
	IsTypeExpr   string `json:"is_type_expr"`
	Condition    string `json:"condition"`
	ScopeStart   int    `json:"scope_start"`
	ScopeEnd     int    `json:"scope_end"`
	Strength     string `json:"strength"`
	FreeLine     int    `json:"free_line"`
	UseLine      int    `json:"use_line"`
	Origin       string `json:"origin"`
	Callee       string `json:"callee"`
	API          string `json:"api"` // hardcoded_secret RegSetValueEx branch
	Name         string `json:"name"`
	Value        string `json:"value"`
	MutexA       string `json:"mutex_a"`
	MutexB       string `json:"mutex_b"`
	ReverseFunc  string `json:"reverse_function"`
	Array        string `json:"array"`
	Index        string `json:"index"`
	KeySize      int    `json:"key_size"`
	Reason       string `json:"reason"`
	CheckFunc    string `json:"check_function"`
	UseFunc      string `json:"use_function"`
	PathArg      string `json:"path_arg"`
	Mutex        string `json:"mutex"`
	LockLine     int    `json:"lock_line"`
	UnlockLine   int    `json:"unlock_line"`
}

func parseEventProps(raw string) eventProps {
	var p eventProps
	_ = json.Unmarshal([]byte(raw), &p)
	return p
}
