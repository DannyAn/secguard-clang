//go:build !nosqlite

package planner

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/apikb"
)

// [nullability.non_null_params] is the project's declaration that a pointer
// parameter name is non-null by an external framework contract (a data-plane
// callback's user_data, an IPC dispatcher's reply_msg). In a BOUNDARY scan
// (no entry point in the tree) every zero-call-site pointer parameter is
// otherwise fail-open, which is the report's single largest null-deref bucket.
//
// The declaration suppresses ONLY that assumption. A call site that
// demonstrably passes literal NULL is evidence, not an assumption, and must
// still surface — the declaration and the witness contradict each other, and
// that contradiction IS the defect.
func TestNullDeref_DeclaredNonNullParamSuppressesBoundaryFailOpen(t *testing.T) {
	apikb.RegisterNonNullParam("zz_nn_user_data")

	src := `typedef struct { unsigned int flag; } ud_t;

int dp_setter(ud_t *zz_nn_user_data)
{
    zz_nn_user_data->flag = 1;
    return 0;
}

int other_setter(ud_t *undeclared_ud)
{
    undeclared_ud->flag = 1;
    return 0;
}
`
	res := planNullDerefFullSrc(t, src)
	varsByFunc := map[string][]string{}
	for _, c := range res.Candidates {
		varsByFunc[c.Target.Function] = append(varsByFunc[c.Target.Function], c.Target.Variable)
	}
	if got := varsByFunc["dp_setter"]; len(got) != 0 {
		t.Errorf("dp_setter: a declared non-null parameter must not seed the boundary fail-open candidate, got %v", got)
	}
	if got := varsByFunc["other_setter"]; len(got) == 0 {
		t.Errorf("other_setter: an UNDECLARED parameter must stay fail-open (control), got %v", varsByFunc)
	}
}

func TestNullDeref_DeclaredNonNullParamStillFlagsLiteralNullCall(t *testing.T) {
	apikb.RegisterNonNullParam("zz_nn_slot")

	src := `typedef struct { unsigned int flag; } ud_t;

void dp_write(ud_t *zz_nn_slot)
{
    zz_nn_slot->flag = 1;
}

void violator(void)
{
    dp_write(NULL);
}
`
	res := planNullDerefFullSrc(t, src)
	for _, c := range res.Candidates {
		if c.Target.Function == "dp_write" {
			return
		}
	}
	t.Errorf("dp_write(NULL): a literal-NULL call site is a WITNESS, not an assumption; it must still surface, got %v", candidateNames(res))
}
