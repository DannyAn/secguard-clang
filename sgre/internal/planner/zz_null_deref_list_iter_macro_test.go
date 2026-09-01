//go:build !nosqlite

package planner

import "testing"

// list_for_each_entry / list_for_each_entry_safe 的定义位于 <linux/list.h> 等
// SDK/系统头文件中，扫描目标 .c 文件时不可见。tree-sitter 把调用点解析成普通
// call_expression；迭代器在宏内被 for-init 重写、被循环条件 null-guard，但分析器
// 看不到宏体，只看到调用前 `line = NULL` 的 null 源，进而在循环体内误报 null-deref。
// 这些宏的迭代器参数由内置知识库(apikb.IteratorMacros)识别并 kill 掉 null 源。
const listIterPreamble = `#include <stdlib.h>

struct list_head { struct list_head *next; struct list_head *prev; };

typedef struct http_line {
    struct list_head link;
    int len;
} http_line_t;

typedef struct http_msg {
    struct list_head header;
} http_msg_t;
`

func TestNullDeref_ListForEachEntryExternalMacro(t *testing.T) {
	src := listIterPreamble + `
int test_check(http_msg_t *msg) {
    http_line_t *line = NULL;
    list_for_each_entry(line, &msg->header, link)
    {
        if (line->len == 1) {
            return 1;
        }
    }
    return 0;
}
`
	result := planNullDerefMacro(t, src)
	if c := candidateForFunc(t, result, "test_check"); c != nil {
		t.Errorf("test_check should NOT be flagged (iterator is reassigned by the macro init and null-checked by the loop condition), got var=%s level=%s", c.Target.Variable, c.SuspicionLevel)
	}
}

func TestNullDeref_ListForEachEntrySafeExternalMacro(t *testing.T) {
	src := listIterPreamble + `
int test_check_safe(http_msg_t *msg) {
    http_line_t *line = NULL;
    http_line_t *next = NULL;
    list_for_each_entry_safe(line, next, &msg->header, link)
    {
        if (line->len == 1) {
            return 1;
        }
    }
    return 0;
}
`
	result := planNullDerefMacro(t, src)
	if c := candidateForFunc(t, result, "test_check_safe"); c != nil {
		t.Errorf("test_check_safe should NOT be flagged (iterator and next cursor are non-null inside the loop), got var=%s level=%s", c.Target.Variable, c.SuspicionLevel)
	}
}

// A bare NULL deref NOT shielded by a traversal macro must still be reported: the
// iterator-macro kill must not silently suppress real null-deref findings.
func TestNullDeref_ListIterMacroKillDoesNotHideRealBug(t *testing.T) {
	src := listIterPreamble + `
int real_bug(http_msg_t *msg) {
    http_line_t *line = NULL;
    if (line->len == 1) {
        return 1;
    }
    return 0;
}
`
	result := planNullDerefMacro(t, src)
	c := candidateForFunc(t, result, "real_bug")
	if c == nil {
		t.Fatalf("expected a null-deref candidate in real_bug(), got: %s", candidateNames(result))
	}
	if c.Target.Variable != "line" {
		t.Errorf("Variable = %q, want line", c.Target.Variable)
	}
}
