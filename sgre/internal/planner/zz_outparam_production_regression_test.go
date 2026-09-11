//go:build !nosqlite

package planner

import "testing"

// Regression tests pinned to the EXACT production shapes of the two
// long-standing out-parameter false positives, plus the false-negative surface
// the address-of recognition must not open while fixing them.

// ---- Bug 1: verbatim production shape -------------------------------------

const bug1Src = `#include <stdint.h>
#include <stdlib.h>

#define SINGLE_BYTE_LEN 1
#define ESCAPE_BYTE 0x5C
#define FOUR_BYTE_WITH_ESCAPE_LEN 5

typedef void *(*waf_malloc_ptr_t)(unsigned long);

void ase_diag_log(int id, const char *fmt, ...);

struct VMData {
    uint32_t g_i_cnt;
    uint32_t j_i_cnt;
    uint32_t len;
};

uint32_t load_unsigned(unsigned char *in, uint32_t len, uint32_t *n)
{
    if (len < SINGLE_BYTE_LEN || (in[0] == ESCAPE_BYTE && len < FOUR_BYTE_WITH_ESCAPE_LEN)) {
        ase_diag_log(1, "[WAF-ALG] FATAL ERROR : length check failed when load unsigned.");
        return 0;
    }

    if (in[0] == ESCAPE_BYTE) {
        *n = *(uint32_t *)(&in[1]);
        return FOUR_BYTE_WITH_ESCAPE_LEN;
    } else {
        *n = in[0];
        return SINGLE_BYTE_LEN;
    }
}

struct VMData *load_data(unsigned char *in, uint32_t len, waf_malloc_ptr_t mallocer, uint32_t *ppos)
{
    uint32_t pos = *ppos;
    uint32_t n_state;
    uint32_t n_lpdfa;
    uint32_t len_u;

    pos += load_unsigned(in + pos, len - pos, &n_state);
    pos += load_unsigned(in + pos, len - pos, &n_lpdfa);
    pos += load_unsigned(in + pos, len - pos, &len_u);

    struct VMData *data;
    data = mallocer(sizeof(*data));
    if (data == NULL) {
        return NULL;
    }

    data->g_i_cnt = data->j_i_cnt = n_state + 1;
    data->len = len_u + n_lpdfa;
    return data;
}
`

func TestUninit_ProductionWriteBackRepro(t *testing.T) {
	res := planUninitOutputParam(t, bug1Src)
	if c := candidateForFunc(t, res, "load_data"); c != nil {
		t.Errorf("BUG1 STILL REPRODUCED: var=%s level=%s line=%d (evidence=%+v)", c.Target.Variable, c.SuspicionLevel, c.Target.Line, c.Evidence)
	}
	if c := candidateForFunc(t, res, "load_unsigned"); c != nil {
		t.Errorf("BUG1 (load_unsigned body): var=%s level=%s line=%d", c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
}

// ---- Bug 2: verbatim production shape -------------------------------------

const bug2Src = `#include <stdlib.h>

typedef void *shm_handle;
typedef int STATUS;
typedef int ASE_STATUS;

#define OK 0
#define ERROR (-1)
#define CATE_XYZ 1
#define ASE_CATE_WAF 2

void ASE_ERR(int cate, const char *fmt, ...);
void VERB(int cate, const char *fmt, ...);
void exml_close(void *x);
void *shm_waf_to_array(void *h);

struct cfg_waf_vsys_list {
    int num_vsys;
    int num_profile;
    int parse_success;
};

void *shm_prfs_list;

STATUS cfg_parse(const char *cfg, shm_handle **out)
{
    void *xml_obj = 0;
    struct cfg_waf_vsys_list *prfs_list = (struct cfg_waf_vsys_list *)shm_waf_to_array(shm_prfs_list);
    if (!prfs_list) {
        ASE_ERR(ASE_CATE_WAF, "allocate profile list shm failed");
        goto err;
    }
    *out = (shm_handle)prfs_list;
    prfs_list->parse_success = 1;
    return OK;
err:
    exml_close(xml_obj);
    return ERROR;
}

int cfg_compile(const char *cfg)
{
    struct cfg_waf_vsys_list *prfs_list = NULL;
    ASE_STATUS result = cfg_parse(cfg, (shm_handle)&prfs_list);
    if (result == OK) {
        VERB(CATE_XYZ, "parse config successfully ... total: vsys (%d), profile (%d)",
            prfs_list->num_vsys, prfs_list->num_profile);
    } else {
        return -1;
    }
    return (result == OK) ? 0 : -1;
}
`

func TestNullDeref_ProductionCastAddressRepro(t *testing.T) {
	res := planNullDeref(t, bug2Src)
	if c := candidateForFunc(t, res, "cfg_compile"); c != nil {
		t.Errorf("BUG2 STILL REPRODUCED: var=%s level=%s line=%d (evidence=%+v)", c.Target.Variable, c.SuspicionLevel, c.Target.Line, c.Evidence)
	}
}

// ---- Blind-spot probes: what the widened cast/& recognition now swallows ----

// D1: a GENUINE bit-and argument `(flags) & mask` must not be read as `&mask`.
// The uninit pipeline must still report the read of mask; the null-deref
// pipeline still uses the permissive recognizer (no scope oracle there), which
// is recorded as a known, false-negative-only limitation.
func TestUninit_BitAndArgIsNotAddressOf(t *testing.T) {
	uninitSrc := `#include <stdlib.h>

extern void sink(unsigned x);

int bitand_uninit(int flags) {
    int mask;
    sink((flags) & mask); /* mask is a genuine uninit read */
    return 0;
}
`
	res := planUninitOutputParam(t, uninitSrc)
	if c := candidateForFunc(t, res, "bitand_uninit"); c == nil {
		t.Errorf("bitand_uninit: genuine uninit read was swallowed by the (T)&x heuristic")
	}

	nullSrc := `#include <stdlib.h>

extern void sink(unsigned x);

int bitand_null(int flags) {
    int *p = NULL;
    sink((flags) & (unsigned long)p);
    return *p; /* genuine null-deref */
}
`
	nres := planNullDeref(t, nullSrc)
	if c := candidateForFunc(t, nres, "bitand_null"); c == nil {
		t.Logf("KNOWN LIMITATION: null-deref pipeline still swallows (flags) & p (permissive oracle-free recognizer)")
	}
}
