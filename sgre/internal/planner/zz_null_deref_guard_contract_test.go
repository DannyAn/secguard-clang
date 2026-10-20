//go:build !nosqlite

package planner

import (
	"testing"
)

// The inter-procedural NULL-return guard contracts (retNullGuardContract):
//
//   - R2 conditional-nonnull getter: the callee returns NULL only under a
//     null check of a pointer parameter and otherwise an address-of value,
//     so a call site inside the argument's own null guard is dismissed.
//   - R3 strip-style helper: the callee returns NULL only under a parameter
//     null check or a strlen(p) >= len overflow check and otherwise forwards
//     a parameter, so a call site with a proven-non-null argument AND the
//     conjunctive early return `strlen(arg) != 0 && lhs == NULL` is
//     dismissed (an overflow implies strlen(arg) != 0, so the guard fires
//     before the dereference).
//
// True-positive controls pin the contracts shut: a range-check getter
// (NULL depends on an id range, not a parameter null check), a global-state
// getter with no parameters, a getter called with a literal NULL argument
// (fail-open), a strip helper without the caller mutex guard, a strip
// helper whose overflow guard is not a strlen test, and a boolean-branch
// guard bypass must all stay reported.
const guardContractFixture = `#include <stddef.h>
#include <string.h>

typedef struct { unsigned int ipv4; } server_addr_t;
typedef struct { int id; server_addr_t addr; } client_info_t;

server_addr_t *get_server_addr(client_info_t *client)
{
    if (client == NULL) {
        return NULL;
    }
    return &client->addr;
}

#define MAX_IP 1024u
typedef struct { unsigned char ipv6[16]; } ip_rec_t;
static ip_rec_t g_table[MAX_IP];

ip_rec_t *find_ip_record(unsigned int id)
{
    if (id >= MAX_IP) {
        return NULL;
    }
    return &g_table[id];
}

static server_addr_t g_addr;
static int g_loaded;

server_addr_t *get_config_addr(void)
{
    if (!g_loaded) {
        return NULL;
    }
    return &g_addr;
}

static char *strip(const char *in, char *buf, size_t len)
{
    if (in == NULL || buf == NULL) {
        return NULL;
    }
    if (strlen(in) >= len) {
        return NULL;
    }
    strcpy(buf, in);
    return buf;
}

static char *strip_lencheck(const char *in, char *buf, size_t len)
{
    if (in == NULL || buf == NULL) {
        return NULL;
    }
    if (len == 0) {
        return NULL;
    }
    strcpy(buf, in);
    return buf;
}

unsigned int use_checked_getter(client_info_t *client)
{
    if (client == NULL) {
        return 0;
    }
    server_addr_t *addr = get_server_addr(client);
    return addr->ipv4;
}

unsigned int use_null_arg(void)
{
    server_addr_t *addr = get_server_addr(NULL);
    return addr->ipv4;
}

int use_strip_checked(const char *user_name)
{
    char buf[64];
    if (user_name == NULL) {
        return -1;
    }
    char *real_name = strip(user_name, buf, sizeof(buf));
    if (strlen(user_name) != 0 && real_name == NULL) {
        return -1;
    }
    return real_name[0] != '\0';
}

int use_strip_unguarded(const char *user_name)
{
    char buf[64];
    if (user_name == NULL) {
        return -1;
    }
    char *real_name = strip(user_name, buf, sizeof(buf));
    return real_name[0] != '\0';
}

int use_strip_lencheck(const char *user_name)
{
    char buf[64];
    if (user_name == NULL) {
        return -1;
    }
    char *real_name = strip_lencheck(user_name, buf, sizeof(buf));
    if (strlen(user_name) != 0 && real_name == NULL) {
        return -1;
    }
    return real_name[0] != '\0';
}

void idm_ip_cmp(unsigned int id)
{
    ip_rec_t *lhs = find_ip_record(id);
    lhs->ipv6[0] = 1;
}

static void sibling_checked(void)
{
    server_addr_t *a = get_config_addr();
    if (a != NULL) {
        a->ipv4 = 1;
    }
}

static void sibling_unchecked(void)
{
    server_addr_t *b = get_config_addr();
    b->ipv4 = 2;
}

static char g_user_name[32];
static int g_has_user;

const char *get_user_name(void)
{
    if (!g_has_user) {
        return NULL;
    }
    return g_user_name;
}

/* id-range getter: the NULL return is guarded by "flag == 0" — a VALUE
 * comparison on an integer parameter, not a null-pointer check. It must NOT
 * qualify for the parameter-null contract (ND-16 regression guard). */
static int g_cfg;

int *find_zero_cfg(int flag)
{
    if (flag == 0) {
        return NULL;
    }
    return &g_cfg;
}

int use_zero_cfg(int flag)
{
    int *cfg = find_zero_cfg(flag);
    *cfg = 1;
    return 0;
}

void process_user_list(int is_all)
{
    const char *usr_name = get_user_name();
    if (!is_all && usr_name == NULL) {
        return;
    }
    if (usr_name[0] == 'a') {
        (void)is_all;
    }
}

int main(void)
{
    client_info_t cli;
    use_checked_getter(&cli);
    use_null_arg();
    use_strip_checked("admin");
    use_strip_unguarded("admin");
    use_strip_lencheck("admin");
    idm_ip_cmp(3);
    g_loaded = 1;
    sibling_checked();
    sibling_unchecked();
    g_has_user = 1;
    process_user_list(0);
    use_zero_cfg(1);
    return 0;
}
`

func TestNullDerefGuardContracts(t *testing.T) {
	result := runRetStrengthPlan(t, map[string]string{"guard_contract.c": guardContractFixture})

	dismissedFns := []string{
		"use_checked_getter", // R2: argument proven non-null
		"use_strip_checked",  // R3: strlen mutex guard at the call site
	}
	for _, fn := range dismissedFns {
		if c, ok := candidateByFunction(result, fn); ok {
			t.Errorf("%s: expected dismissal by the callee NULL-return guard contract, got kept candidate (tier %q)", fn, c.NullOriginTier)
		}
		if !droppedByFunction(result, fn) {
			t.Errorf("%s: expected a dropped entry for the guard-contract dismissal, got candidates: %v", fn, candidateNames(result))
		}
	}

	keptFns := []string{
		"use_null_arg",        // literal NULL argument: fail-open
		"use_strip_unguarded", // no caller mutex guard
		"use_strip_lencheck",  // callee overflow guard is not a strlen test
		"idm_ip_cmp",          // TP-1: range-check getter consumed unguarded
		"sibling_unchecked",   // TP-2: global-state getter, unchecked sibling
		"process_user_list",   // TP-3: boolean branch bypasses the guard
		"use_zero_cfg",        // ND-16: `flag == 0` value comparison is not a null check
	}
	for _, fn := range keptFns {
		if _, ok := candidateByFunction(result, fn); !ok {
			t.Errorf("%s: expected a kept candidate (true-positive control), got candidates: %v (dropped=%v)", fn, candidateNames(result), droppedByFunction(result, fn))
		}
	}
}
