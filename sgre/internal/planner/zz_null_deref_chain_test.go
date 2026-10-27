//go:build !nosqlite

package planner

import (
	"strings"
	"testing"
)

// A function reached through TWO independent chains (a direct call AND a
// callback registration) must show EVERY caller: the reported real null-deref
// was dismissed because the classifier applied a sibling chain's guard (a count
// check in proc_entry) to the sinks reached through the UNGUARDED callback
// chain. The candidate must carry chain-root@ + sibling-callers@ so that is
// visible from the row.
func TestNullDeref_SiblingChainCallers(t *testing.T) {
	src := `#include <string.h>
struct Node { char name[32]; int parent; int layer; };
struct ExtAckMsg { unsigned int count; unsigned int data_len; void *data; };
struct Para { int x; };
extern int some_cond(struct Para *);
extern int get_base_path(struct Para *, char *, unsigned long);
extern int get_path(struct Para *, char *, const char *, char *, unsigned long);
extern int recv_resp(struct Para *, void (*cb)(struct ExtAckMsg *, struct Para *), void *);
int refresh_tree(struct ExtAckMsg *resp, struct Para *para)
{
    struct Node *tree = (struct Node *)(resp->data);
    if (some_cond(para)) {
        char basepath[33];
        if (get_base_path(para, basepath, sizeof(basepath)) != 0) return -1;
        strcpy(tree[0].name, basepath);
    }
    char path[33];
    if (get_path(para, (char *)tree[0].name, "", path, sizeof(path)) != 0) return -1;
    strcpy(tree[0].name, path);
    return 0;
}
static int list_proc_callback(struct ExtAckMsg *resp, struct Para *para)
{
    return refresh_tree(resp, para);
}
static int proc_entry(struct ExtAckMsg *resp, struct Para *para)
{
    if (resp->count == 0) return 0;
    if (resp->count * sizeof(struct Node) != resp->data_len) return 0;
    return refresh_tree(resp, para);
}
static void list_main(struct Para *para)
{
    recv_resp(para, list_proc_callback, (void *)para);
}
int init_entry(void)
{
    struct Para p = {0};
    list_main(&p);
    return 0;
}
int usrgroup_entry(struct ExtAckMsg *resp, struct Para *para)
{
    return proc_entry(resp, para);
}
`
	res := planNullDerefFullSrc(t, src)
	var tree *EvidenceItem
	for i := range res.Candidates {
		if res.Candidates[i].Target.Function == "refresh_tree" && res.Candidates[i].Target.Variable == "tree" {
			tree = &res.Candidates[i]
		}
	}
	if tree == nil {
		t.Fatalf("expected the `tree` null-deref candidate in refresh_tree")
	}
	if !strings.Contains(tree.Hint, "chain-root@list_proc_callback") {
		t.Errorf("hint must name the candidate's chain root; got %q", tree.Hint)
	}
	if !strings.Contains(tree.Hint, "sibling-callers@proc_entry") {
		t.Errorf("hint must name the sibling caller chain (proc_entry); got %q", tree.Hint)
	}
	var siblingEvidence bool
	for _, f := range tree.Evidence {
		if strings.Contains(f.Detail, "ALSO called from proc_entry") && strings.Contains(f.Detail, "does NOT protect") {
			siblingEvidence = true
		}
	}
	if !siblingEvidence {
		t.Errorf("evidence must state that a sibling chain's guard does not protect this candidate; got %+v", tree.Evidence)
	}
}

// A single-caller function must NOT carry the chain tokens (the chain is
// unambiguous, and adding them to every row would be noise).
func TestNullDeref_SingleChainNoTokens(t *testing.T) {
	src := `struct S { int *p; };
int get(struct S *s) {
    int *q = s->p;
    return *q;
}
int main(void) {
    struct S s = {0};
    return get(&s);
}
`
	res := planNullDerefFullSrc(t, src)
	for _, c := range res.Candidates {
		if c.Target.Function == "get" {
			if strings.Contains(c.Hint, "chain-root@") || strings.Contains(c.Hint, "sibling-callers@") {
				t.Errorf("single-caller function must not carry chain tokens; got %q", c.Hint)
			}
		}
	}
}
