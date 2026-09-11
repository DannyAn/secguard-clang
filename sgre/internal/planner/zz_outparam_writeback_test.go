//go:build !nosqlite

package planner

import "testing"

// Pinned interprocedural write-back behavior: a callee that assigns the
// caller's variable through an address-taken parameter (`f(&x)` + `*p = v`)
// must initialize / re-type that variable at the call site, in both the uninit
// and the null-deref pipelines. Covers the two production dogfood false
// positives: the unguarded conditional writer (`pos += load(&n_state)`) and
// the cast-typed address argument (`cfg_parse(cfg, (shm_handle)&prfs_list)`).

// TestUninit_WriteBackViaOutParam: load_unsigned writes *n on both of its
// non-early-return branches; the caller consumes the returned byte count and
// reads n_state/n_lpdfa/len_u afterwards. These reads must NOT be reported as
// uninitialized.
func TestUninit_WriteBackViaOutParam(t *testing.T) {
	src := `#include <stdint.h>
#include <stdlib.h>

struct VMData { uint32_t g_i_cnt; uint32_t j_i_cnt; uint32_t len; };

static uint32_t load_unsigned(unsigned char *in, uint32_t len, uint32_t *n)
{
    if (len < 1) {
        return 0;
    }
    if (in[0] == 0xFF) {
        *n = *(uint32_t *)(&in[1]);
        return 4;
    } else {
        *n = in[0];
        return 1;
    }
}

uint32_t load_data(unsigned char *in, uint32_t len)
{
    uint32_t pos = 0;
    uint32_t n_state;
    uint32_t n_lpdfa;
    uint32_t len_u;
    struct VMData *data;

    pos += load_unsigned(in + pos, len - pos, &n_state);
    pos += load_unsigned(in + pos, len - pos, &n_lpdfa);
    pos += load_unsigned(in + pos, len - pos, &len_u);

    data = (struct VMData *)malloc(sizeof(*data));
    if (data == NULL) {
        return 0;
    }
    data->g_i_cnt = data->j_i_cnt = n_state + 1;
    data->len = len_u + n_lpdfa;
    return pos;
}
`
	result := planUninitOutputParam(t, src)
	if c := candidateForFunc(t, result, "load_data"); c != nil {
		t.Errorf("load_data must NOT be flagged (n_state/n_lpdfa/len_u are written by load_unsigned through &n), got var=%s level=%s line=%d", c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
}

// TestNullDeref_WriteBackViaOutParam: cfg_parse stores a non-null pointer into
// *out (the caller's prfs_list, passed as (shm_handle)&prfs_list); reading
// prfs_list->num_vsys after the OK check must NOT be a null-deref.
func TestNullDeref_WriteBackViaOutParam(t *testing.T) {
	src := `#include <stdlib.h>

typedef void *shm_handle;
typedef int STATUS;
#define OK 0
#define ERROR (-1)
typedef int ASE_STATUS;

struct cfg_waf_vsys_list { int num_vsys; int num_profile; int parse_success; };

static STATUS cfg_parse(const char *cfg, shm_handle *out)
{
    struct cfg_waf_vsys_list *prfs_list = (struct cfg_waf_vsys_list *)malloc(sizeof(*prfs_list));
    if (!prfs_list) {
        return ERROR;
    }
    *out = (shm_handle)prfs_list;
    prfs_list->parse_success = 1;
    return OK;
}

int cfg_compile(const char *cfg)
{
    struct cfg_waf_vsys_list *prfs_list = NULL;
    ASE_STATUS result = cfg_parse(cfg, (shm_handle)&prfs_list);
    if (result == OK) {
        return prfs_list->num_vsys + prfs_list->num_profile;
    }
    return -1;
}
`
	result := planNullDeref(t, src)
	if c := candidateForFunc(t, result, "cfg_compile"); c != nil {
		t.Errorf("cfg_compile must NOT be flagged (prfs_list is written by cfg_parse through &prfs_list on the OK path), got var=%s level=%s line=%d", c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
}

// TestUninit_WriteBackViaCastOutParam: the address argument spelled with a
// type cast parses as a BIT-AND binary_expression when the cast target is a
// bare identifier (`(shm_handle)&n` has no pointer_expression child).
// tree-sitter-c emits that same parse for a genuine bit-and, so this shape is
// resolved by scope, not by syntax: `shm_handle` is a type name, never a
// variable. The out-param recognition must still see the address-of, or the
// call line itself is misread as a use-before-init of n.
func TestUninit_WriteBackViaCastOutParam(t *testing.T) {
	src := `#include <stdint.h>

typedef void *blob_handle;

static void blob_load(const unsigned char *in, uint32_t len, blob_handle *out)
{
    if (len == 0) {
        return;
    }
    *out = (blob_handle)(unsigned long)in[0];
}

uint32_t blob_init(const unsigned char *in, uint32_t len)
{
    uint32_t n;
    blob_load(in, len, (blob_handle)&n);
    return n + 1;
}
`
	result := planUninitOutputParam(t, src)
	if c := candidateForFunc(t, result, "blob_init"); c != nil {
		t.Errorf("blob_init must NOT be flagged (n is written by blob_load through the cast-typed &n), got var=%s level=%s line=%d", c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
}
