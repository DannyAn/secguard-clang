package planner

// ProofClass enumerates the four deterministic proof techniques sanctioned by
// AI_JUDGMENT_BOUNDARY.md. A filter that promotes a candidate to "confirmed"
// must do so via exactly one of these classes; any other "confirmed" upgrade
// is a heuristic and must stay suspected.
type ProofClass string

const (
	// ProofClassCFGMustDataflow: the fact holds on EVERY CFG path (must-null,
	// must-freed, must-uninit, definite leak, taint reaching a sink on all
	// paths, a lock-order cycle, a shared-global write race, ...).
	ProofClassCFGMustDataflow ProofClass = "cfg-must-dataflow"
	// ProofClassInterval: integer interval / constant folding proves the fact
	// (divisor always zero, index lo >= capacity, literal arithmetic overflow).
	ProofClassInterval ProofClass = "interval-or-const-fold"
	// ProofClassLiteral: the literal itself carries the defect (weak crypto
	// algorithm, hardcoded secret whose value is secret-shaped, sizeof(ptr),
	// signed/unsigned comparison with provable sign).
	ProofClassLiteral ProofClass = "literal"
	// ProofClassTypeInherent: the call is a defect by name / signature alone
	// (signal-handler async-unsafe API, dangerous-function banned call, an
	// unchecked return with a known callee failure contract).
	ProofClassTypeInherent ProofClass = "type-inherent"
)

// AllProofClasses is the closed set TestDynamicConfirmedUpgradesRegistered
// validates against.
var AllProofClasses = []ProofClass{
	ProofClassCFGMustDataflow,
	ProofClassInterval,
	ProofClassLiteral,
	ProofClassTypeInherent,
}

// IsValid reports whether c is one of the four sanctioned classes.
func (c ProofClass) IsValid() bool {
	for _, k := range AllProofClasses {
		if c == k {
			return true
		}
	}
	return false
}

// Proof is one auditable deterministic-verdict record: a filter that upgrades
// a candidate to "confirmed" declares, per upgrade rule, the proof class and
// a test that exercises the rule.
type Proof struct {
	// Class is one of the four ProofClass values.
	Class ProofClass
	// Rule is a short kebab-case rule identifier, unique within the filter
	// (e.g. "must-null-on-all-paths", "divisor-always-zero").
	Rule string
	// Evidence is a one-sentence human-readable description of the proof
	// shape (what graph/interval/literal fact carries the verdict).
	Evidence string
	// TestRef is the name of a Go test (TestXxx) that exercises this upgrade
	// path; TestDynamicConfirmedUpgradesRegistered asserts the test exists.
	TestRef string
}

// ProofRegistrar is implemented by any Filter that can promote a candidate
// to "confirmed" during Apply. The returned list is the filter's public
// contract with the AI judgment boundary: every upgrade path must appear
// here, with its proof class registered.
type ProofRegistrar interface {
	// DeclaredProofs returns every proof this filter may use to upgrade a
	// candidate to "confirmed". An empty slice means the filter never upgrades
	// (all its candidates stay at their seeded suspicion tier).
	DeclaredProofs() []Proof
}
