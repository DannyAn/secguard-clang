//go:build !nosqlite

package planner

import (
	"testing"
)

// Cross-file regression for the reported false positive: a function output
// parameter (written on every path in the callee) misreported as an
// uninitialized read at the caller, where the caller declares the SAME local
// name in two sibling blocks. The scope-aware detector keys each fact to its
// declaration line so one block's output-param init line cannot suppress the
// other block's use, and the interprocedural summary (built across files) must
// mark the callee's flag param as written on every path.
const outParamAPISrc = `#include <stdint.h>

int is_type_a(const char *t) { return t && t[0] == 'a'; }
uint32_t get_type_a_value(const char *t, uint32_t *a, uint32_t *b) { *a = 1; *b = 2; return 0; }
uint32_t get_type_b_value(const char *t, uint32_t *a, uint32_t *b) { *a = 3; *b = 4; return 0; }

uint32_t get_value_by_str(const char *input, uint8_t *flag, uint32_t *out1, uint32_t *out2)
{
    if (is_type_a(input)) {
        *flag = 1;
        return get_type_a_value(input, out1, out2);
    } else {
        *flag = 0;
        return get_type_b_value(input, out1, out2);
    }
}
`

const outParamUsageSrc = `#include <stdint.h>
#include <string.h>

typedef struct { uint32_t *val1; uint32_t *val2; uint32_t type; } condition;

int is_valid_input(const char *t) { return t && *t; }
uint32_t get_value_by_str(const char *input, uint8_t *flag, uint32_t *out1, uint32_t *out2);

uint32_t process_input(const char *text, const char *type_str,
                       condition *cond, uint8_t *cond_num)
{
    if (text == NULL || strlen(text) == 0) {
        return 0;
    }

    uint32_t ret = 1;
    if (type_str == NULL || strlen(type_str) == 0) {
        if (is_valid_input(text)) {
            uint8_t version;
            ret = get_value_by_str(text, &version, cond->val1, cond->val2);
            cond->type = (version == 1) ? 11 : 22;
        } else {
            ret = 0;
            cond->type = 33;
        }
    }

    uint32_t type = 0;
    if (type_str != NULL && strlen(type_str) != 0) {
        if (type >= 10) {
            return 1;
        }
        if (type == 33) {
            ret = 0;
            cond->type = 33;
        } else if (is_valid_input(text)) {
            uint8_t version;
            ret = get_value_by_str(text, &version, cond->val1, cond->val2);
            cond->type = (version == 1) ? 11 : 22;
        }
    }

    if (ret != 0) {
        return 1;
    }

    *cond_num = *cond_num + 1;
    return 0;
}
`

func TestUninit_OutParamIfElseShadowedCrossFile(t *testing.T) {
	result := planUninitMacroFiles(t, map[string]string{
		"xxx_api.c":   outParamAPISrc,
		"xxx_usage.c": outParamUsageSrc,
	})
	for _, c := range result.Candidates {
		if c.Target.Variable == "version" {
			t.Errorf("version must not be reported as uninit when filled via &version output-param across files, got candidate line %d", c.Target.Line)
		}
	}
}
