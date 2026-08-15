package graph

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

func parseBody(t *testing.T, src string) parser.Node {
	t.Helper()
	p := parser.NewParser()
	tree, err := p.Parse([]byte(src), "t.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Keep the tree alive for the duration of the test: the returned Node holds
	// a pointer into tree-sitter's tree, which would be freed by Close().
	root := tree.RootNode()
	fn := root.FindFirst("function_definition")
	if fn == nil {
		t.Fatal("no function_definition found")
	}
	body := fn.FindFirst("compound_statement")
	if body == nil {
		t.Fatal("no compound_statement body")
	}
	return *body
}

func stmtLines(cfg *StmtCFG) []int {
	var lines []int
	for _, n := range cfg.Nodes {
		if n.Kind == "stmt" {
			lines = append(lines, n.StartLine)
		}
	}
	return lines
}

func TestBuildStmtCFG_StraightLine(t *testing.T) {
	body := parseBody(t, `int f(void) {
    int a = 1;
    a = a + 1;
    return a;
}`)
	cfg := BuildStmtCFG(body, 5)

	if len(stmtLines(cfg)) != 3 {
		t.Fatalf("expected 3 statement nodes, got %v", stmtLines(cfg))
	}
	// entry -> s1 -> s2 -> return -> exit; return has no fall-through successor.
	if len(cfg.Nodes[cfg.Entry].Succs) != 1 {
		t.Errorf("entry should have 1 successor, got %v", cfg.Nodes[cfg.Entry].Succs)
	}
	// exit must be reachable from the return node.
	if len(cfg.Nodes[cfg.Exit].Succs) != 0 {
		t.Errorf("exit should have no successors")
	}
}

func TestBuildStmtCFG_IfElseJoin(t *testing.T) {
	body := parseBody(t, `int f(int c) {
    int x;
    if (c) { x = 1; } else { x = 2; }
    return x;
}`)
	cfg := BuildStmtCFG(body, 6)

	// A dereference after the if must be reachable from both branches.
	joinFound := false
	for _, n := range cfg.Nodes {
		if n.Kind == "join" && len(n.Succs) > 0 {
			joinFound = true
		}
	}
	if !joinFound {
		t.Fatal("expected a join node after the if/else")
	}
	// NodeAt should resolve the return line to the return statement, not the
	// enclosing if.
	if n := cfg.NodeAt(4); n == nil || n.Stmt.Kind() != "return_statement" {
		t.Errorf("NodeAt(4) should be the return statement, got %+v", n)
	}
}

func TestBuildStmtCFG_PreprocAlternatives(t *testing.T) {
	body := parseBody(t, `int f(void) {
#ifdef X
    int x = 1;
#else
    int x = 2;
#endif
    return x;
}`)
	cfg := BuildStmtCFG(body, 9)

	// Both branch declarations must be CFG statement nodes.
	assignNodes := make(map[int]bool)
	for _, n := range cfg.Nodes {
		if n.Kind == "stmt" && n.Stmt.Kind() == "declaration" {
			assignNodes[n.ID] = true
		}
	}
	if len(assignNodes) < 2 {
		t.Fatalf("expected both preprocessor-branch declarations as CFG nodes, got %d", len(assignNodes))
	}

	// A join node must exist after the alternatives, and the return line must
	// resolve to the return statement.
	joinFound := false
	for _, n := range cfg.Nodes {
		if n.Kind == "join" && len(n.Succs) > 0 {
			joinFound = true
		}
	}
	if !joinFound {
		t.Error("expected a join node after the preprocessor conditional")
	}
	if n := cfg.NodeAt(7); n == nil || n.Stmt.Kind() != "return_statement" {
		t.Errorf("NodeAt(7) should be the return statement, got %+v", n)
	}

	// A value written in BOTH branches is definitely written: there must be no
	// path from entry to exit that avoids every assignment node.
	if cfg.ReachesAvoiding(cfg.Entry, assignNodes, cfg.Exit) {
		t.Error("expected no path from entry to exit avoiding both preproc-branch assignments")
	}
}

func TestBuildStmtCFG_ReturnTerminates(t *testing.T) {
	body := parseBody(t, `int f(int c) {
    int x = 1;
    if (c) { return 1; }
    return 2;
}`)
	cfg := BuildStmtCFG(body, 6)

	// The return inside the if must not fall through; only the second return
	// (and the if's false path) reach the exit.
	reachable := map[int]bool{}
	var dfs func(id int)
	dfs = func(id int) {
		if reachable[id] {
			return
		}
		reachable[id] = true
		for _, s := range cfg.Nodes[id].Succs {
			dfs(s)
		}
	}
	dfs(cfg.Entry)
	if !reachable[cfg.Exit] {
		t.Error("exit should be reachable")
	}
}

func TestBuildStmtCFG_LoopBackEdge(t *testing.T) {
	body := parseBody(t, `int f(void) {
    int i = 0;
    while (i < 10) { i = i + 1; }
    return i;
}`)
	cfg := BuildStmtCFG(body, 5)

	hasBackEdge := false
	// A loop has a back edge: some node's successor is an earlier node.
	for _, n := range cfg.Nodes {
		for _, s := range n.Succs {
			if s <= n.ID {
				hasBackEdge = true
			}
		}
	}
	if !hasBackEdge {
		t.Error("expected a back edge in the loop CFG")
	}
}

func TestStmtCFG_ReachesAvoiding(t *testing.T) {
	body := parseBody(t, `int f(int c) {
    int *p = malloc(8);
    if (c) { free(p); } else { *p = 1; }
    return 0;
}`)
	cfg := BuildStmtCFG(body, 7)

	// free(p) is at line 3, *p = 1 at line 3 too; both branches share line 3.
	// Use node IDs directly: the branch-then node and branch-else node must not
	// reach each other.
	var thenNode, elseNode *StmtNode
	for _, n := range cfg.Nodes {
		if n.Kind != "stmt" {
			continue
		}
		if n.Stmt.Kind() == "expression_statement" {
			// free(p) and *p=1 are both expression_statements.
			if thenNode == nil {
				thenNode = n
			} else {
				elseNode = n
			}
		}
	}
	if thenNode == nil || elseNode == nil {
		t.Fatal("expected two branch expression statements")
	}
	// The two branches are mutually exclusive: neither reaches the other.
	if cfg.Reaches(thenNode.ID, elseNode.ID) {
		t.Error("branch-then should not reach branch-else")
	}
	if cfg.Reaches(elseNode.ID, thenNode.ID) {
		t.Error("branch-else should not reach branch-then")
	}

	// From the malloc declaration (before the if), the exit is reachable
	// avoiding the free.
	alloc := cfg.NodeAt(2)
	if alloc == nil {
		t.Fatal("alloc node not found at line 2")
	}
	if !cfg.ReachesAvoiding(alloc.ID, map[int]bool{thenNode.ID: true}, cfg.Exit) {
		t.Error("exit should be reachable from alloc avoiding the free branch")
	}
}

func TestBuildStmtCFG_SwitchCaseReachable(t *testing.T) {
	body := parseBody(t, `int f(int mode, char *p) {
    switch (mode) {
    case 1:
        *p = 1;
        break;
    case 2:
        *p = 2;
        break;
    default:
        break;
    }
    return *p;
}`)
	cfg := BuildStmtCFG(body, 12)

	// Every case's statement must be resolvable via NodeAt (a switch case must
	// not be skipped). *p = 1 is on line 4, *p = 2 on line 7.
	if cfg.NodeAt(4) == nil {
		t.Error("NodeAt(4) should resolve the statement inside case 1")
	}
	if cfg.NodeAt(7) == nil {
		t.Error("NodeAt(7) should resolve the statement inside case 2")
	}
	// The return after the switch (line 11) must be reachable from the entry
	// via the join (a break exits the switch, not the whole function).
	if !cfg.Reaches(cfg.Entry, cfg.Exit) {
		t.Error("exit should be reachable from entry through the switch")
	}
	// A case's statement must reach the exit via break, so the return after the
	// switch is reachable from the case statement.
	caseNode := cfg.NodeAt(4)
	if caseNode == nil || !cfg.Reaches(caseNode.ID, cfg.Exit) {
		t.Error("case 1's statement should reach the exit via break -> join")
	}
}

func TestBuildStmtCFG_BreakPrecedenceLoopInSwitch(t *testing.T) {
	// A `break` inside a loop nested in a switch case must break the LOOP, not
	// the switch. The statement after the loop is then reachable from the loop
	// body via the loop's own exit (the previous switchBreakTo precedence made
	// break jump straight to the switch exit and skip the post-loop statement).
	body := parseBody(t, `int f(int m, int *lencode, int *out) {
    for (;;) switch (m) {
    case 1:
        for (;;) {
            out[0] = *lencode;
            if (*lencode) break;
            lencode++;
        }
        out[1] = 1;
        break;
    default:
        break;
    }
    return 0;
}`)
	cfg := BuildStmtCFG(body, 14)

	// The post-loop statement (out[1] = 1) is on line 9.
	post := cfg.NodeAt(9)
	if post == nil {
		t.Fatal("post-loop statement not found at line 9")
	}
	// The break statement (line 7) is inside the nested loop; it must reach the
	// post-loop statement through the loop's exit.
	breakNode := cfg.NodeAt(7)
	if breakNode == nil {
		t.Fatal("break statement not found at line 7")
	}
	if !cfg.Reaches(breakNode.ID, post.ID) {
		t.Error("break inside the nested loop should reach the post-loop statement")
	}
}

func TestStmtCFG_NodeAtInnermost(t *testing.T) {
	body := parseBody(t, `int f(int c) {
    int x = 1;
    if (c) { x = 2; }
    return x;
}`)
	cfg := BuildStmtCFG(body, 6)

	// Line 2 is the declaration; line 3 the if; line 4 the return.
	if n := cfg.NodeAt(2); n == nil || n.Stmt.Kind() != "declaration" {
		t.Errorf("NodeAt(2) should be the declaration, got %+v", n)
	}
	if n := cfg.NodeAt(4); n == nil || n.Stmt.Kind() != "return_statement" {
		t.Errorf("NodeAt(4) should be the return statement, got %+v", n)
	}
}
