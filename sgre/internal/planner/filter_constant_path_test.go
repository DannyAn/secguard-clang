//go:build !nosqlite

package planner

import (
	"strings"
	"testing"
)

// constantPathDrops returns the `constant_path_proof` dismissals of a plan.
func constantPathDrops(result *PlanResult) []Dismissed {
	var out []Dismissed
	for _, d := range result.Summary.Dropped {
		if d.Filter == "constant_path_proof" {
			out = append(out, d)
		}
	}
	return out
}

func constantPathDroppedByFunction(result *PlanResult, filter, fn string) bool {
	for _, d := range result.Summary.Dropped {
		if d.Filter == filter && d.FunctionName == fn {
			return true
		}
	}
	return false
}

// TestConstantPath_HelperBuiltFixedPathDropped locks in the production
// false-positive shape: a filesystem sink receives a path PARAMETER, every
// in-tree caller passes a local buffer (so the call-site census is
// `N:M-var`, not all-literal), and that buffer is assembled from a fixed
// directory plus a constant file name — the file name coming from a
// switch-of-literals helper and the assembly from a path-building helper.
// No user-controlled component exists, so the candidate must be dropped.
func TestConstantPath_HelperBuiltFixedPathDropped(t *testing.T) {
	src := `#include <stdio.h>

#define EXPORT_DIR "/var/export"

static const char *csv_name(int kind) {
    switch (kind) {
        case 1: return "thrt_org.csv";
        case 2: return "trf_topn.csv";
        default: return "policy_topn.csv";
    }
}

static void build_export_path(int kind, char *out, unsigned cap) {
    snprintf(out, cap, "%s/%s", EXPORT_DIR, csv_name(kind));
}

unsigned export2file(const char *export_path) {
    FILE *f = fopen(export_path, "w");
    if (f == NULL) {
        return 1;
    }
    fclose(f);
    return 0;
}

int run_export(int kind) {
    char export_path[512] = {0};
    build_export_path(kind, export_path, sizeof export_path);
    return (int)export2file(export_path);
}
`
	result := setupCallsiteFixture(t, src, "path-traversal")
	if _, ok := candidatesByFunc(result)["export2file"]; ok {
		t.Fatalf("export2file (parameter resolved to a constant path chain) should be dropped, got %v", candidateNames(result))
	}
	if !constantPathDroppedByFunction(result, "constant_path_proof", "export2file") {
		t.Fatalf("export2file drop must be attributed to the constant_path_proof filter, got %+v", result.Summary.Dropped)
	}
	drops := constantPathDrops(result)
	if len(drops) == 0 || !strings.Contains(drops[0].Reason, "compile-time constant") {
		t.Fatalf("the drop reason must state the constant-path proof, got %+v", drops)
	}
}

// TestConstantPath_UserInputChainKept is the counter-example the issue calls
// out: the one real CWE-22 is a JSON field flowing through a suffix-only check
// into a fixed-directory path. Nothing in that chain is a compile-time
// constant, so the candidate must survive the proof and reach the AI.
func TestConstantPath_UserInputChainKept(t *testing.T) {
	src := `#include <stdio.h>
#include <string.h>

struct json_obj;

const char *custom_pdf_path(void);
char *json_get_string_by_key(struct json_obj *node, const char *key);

int file_is_exist(const char *name) {
    FILE *handle = fopen(name, "rb");
    if (handle == NULL) {
        return 0;
    }
    fclose(handle);
    return 1;
}

int custom_delete_pdf_file(char *file_name) {
    const char *pdf_dir = custom_pdf_path();
    char pdf_path[512];
    snprintf(pdf_path, sizeof pdf_path, "%s/%s", pdf_dir, file_name);
    return file_is_exist(pdf_path);
}

int del_custom_file_cb(void *input) {
    char *file_name = json_get_string_by_key((struct json_obj *)input, "file_name");
    if (file_name == NULL || strstr(file_name, ".pdf") == NULL) {
        return -1;
    }
    return custom_delete_pdf_file(file_name);
}
`
	result := setupCallsiteFixture(t, src, "path-traversal")
	if _, ok := candidatesByFunc(result)["file_is_exist"]; !ok {
		t.Fatalf("file_is_exist (user-controlled JSON field reaches the sink) must be kept, got %v", candidateNames(result))
	}
	if len(constantPathDrops(result)) != 0 {
		t.Fatalf("no candidate may be dropped by constant_path_proof here, got %+v", constantPathDrops(result))
	}
}

// TestConstantPath_UnknownRuntimeComponentKept locks the one-directional proof:
// a caller that builds the path from an UNKNOWN runtime value (an external
// function result) blocks the drop even though the fixed prefix is constant.
func TestConstantPath_UnknownRuntimeComponentKept(t *testing.T) {
	src := `#include <stdio.h>

#define DEVICE_DIR "/var/device"

const char *device_serial(void);

unsigned open_report(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return 1;
    }
    fclose(f);
    return 0;
}

int report_once(void) {
    char path[256];
    snprintf(path, sizeof path, "%s/%s.txt", DEVICE_DIR, device_serial());
    return (int)open_report(path);
}
`
	result := setupCallsiteFixture(t, src, "path-traversal")
	if _, ok := candidatesByFunc(result)["open_report"]; !ok {
		t.Fatalf("open_report (path carries an unknown runtime value) must be kept, got %v", candidateNames(result))
	}
	if len(constantPathDrops(result)) != 0 {
		t.Fatalf("constant_path_proof must not drop an unknown runtime component, got %+v", constantPathDrops(result))
	}
}

// TestConstantPath_InternallyGeneratedCounterDropped locks the
// "internally generated value" half of the request: a fixed directory plus a
// timestamp formatted through an integer conversion cannot carry a path
// separator, so the chain is a compile-time-constant path.
func TestConstantPath_InternallyGeneratedCounterDropped(t *testing.T) {
	src := `#include <stdio.h>
#include <time.h>

#define STAT_DIR "/var/lib/stats"

unsigned open_stat(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return 1;
    }
    fclose(f);
    return 0;
}

static void build_stat_path(char *out, unsigned cap) {
    snprintf(out, cap, "%s/%u.json", STAT_DIR, (unsigned)time(NULL));
}

int tick(void) {
    char stat_path[256];
    build_stat_path(stat_path, sizeof stat_path);
    return (int)open_stat(stat_path);
}
`
	result := setupCallsiteFixture(t, src, "path-traversal")
	if _, ok := candidatesByFunc(result)["open_stat"]; ok {
		t.Fatalf("open_stat (fixed dir + numeric counter) should be dropped, got %v", candidateNames(result))
	}
	if !constantPathDroppedByFunction(result, "constant_path_proof", "open_stat") {
		t.Fatalf("open_stat drop must be attributed to constant_path_proof, got %+v", result.Summary.Dropped)
	}
}

// TestConstantPath_OverwrittenParamDropped locks the parameter-write rule: when
// the sink's own function OVERWRITES its path parameter from constants, the
// caller's argument no longer reaches the sink, so the path is constant
// regardless of what callers pass.
func TestConstantPath_OverwrittenParamDropped(t *testing.T) {
	src := `#include <stdio.h>

#define RPT_DIR "/var/reports"

unsigned save_bytes(const char *report_name) {
    char path[512] = {0};
    snprintf(path, sizeof path, "%s/%s", RPT_DIR, report_name);
    FILE *f = fopen(path, "w");
    if (f == NULL) {
        return 1;
    }
    fclose(f);
    return 0;
}

int main(void) {
    return (int)save_bytes("rpt.json");
}
`
	result := setupCallsiteFixture(t, src, "path-traversal")
	if _, ok := candidatesByFunc(result)["save_bytes"]; ok {
		t.Fatalf("save_bytes (parameter overwritten with a constant-built path) should be dropped, got %v", candidateNames(result))
	}
	if !constantPathDroppedByFunction(result, "constant_path_proof", "save_bytes") {
		t.Fatalf("save_bytes drop must be attributed to constant_path_proof, got %+v", result.Summary.Dropped)
	}
}

// TestConstantPath_NoInTreeCallerKept locks the external-ABI boundary: a
// parameter with no in-tree call site is not provable (an out-of-scan
// translation unit may pass anything), so the candidate stays.
func TestConstantPath_NoInTreeCallerKept(t *testing.T) {
	src := `#include <stdio.h>

void tp_path_traversal(const char *path) {
    FILE *f = fopen(path, "r");
    if (f) {
        fclose(f);
    }
}
`
	result := setupCallsiteFixture(t, src, "path-traversal")
	if _, ok := candidatesByFunc(result)["tp_path_traversal"]; !ok {
		t.Fatalf("tp_path_traversal (zero in-tree callers) must be kept, got %v", candidateNames(result))
	}
}

// TestConstantPath_ExternalWriterKept locks the write model: passing the path
// buffer to a function with no in-tree body may overwrite it with anything, so
// the value is not provable even though every argument visible here is
// constant.
func TestConstantPath_ExternalWriterKept(t *testing.T) {
	src := `#include <stdio.h>

void fill_path(char *buf, unsigned cap);

unsigned consume_path(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return 1;
    }
    fclose(f);
    return 0;
}

int run(void) {
    char p[128];
    fill_path(p, sizeof p);
    return (int)consume_path(p);
}
`
	result := setupCallsiteFixture(t, src, "path-traversal")
	if _, ok := candidatesByFunc(result)["consume_path"]; !ok {
		t.Fatalf("consume_path (buffer written by an out-of-tree function) must be kept, got %v", candidateNames(result))
	}
	if len(constantPathDrops(result)) != 0 {
		t.Fatalf("constant_path_proof must not assume an unmodeled function leaves the buffer untouched, got %+v", constantPathDrops(result))
	}
}

// TestConstantPath_AllLiteralCallersStillDropped is the regression guard for the
// pre-existing call-site census gate: the new filter must not re-introduce a
// candidate that the all-literal census already dropped.
func TestConstantPath_AllLiteralCallersStillDropped(t *testing.T) {
	src := `#include <stdio.h>

unsigned read_cfg(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return 1;
    }
    fclose(f);
    return 0;
}

int main(void) {
    return (int)read_cfg("/etc/app.conf");
}
`
	result := setupCallsiteFixture(t, src, "path-traversal")
	if _, ok := candidatesByFunc(result)["read_cfg"]; ok {
		t.Fatalf("read_cfg (all in-tree call sites literal) should stay dropped, got %v", candidateNames(result))
	}
	if !constantPathDroppedByFunction(result, "taint_source", "read_cfg") {
		t.Fatalf("the all-literal drop must remain attributed to the census gate, got %+v", result.Summary.Dropped)
	}
}

// TestConstantPath_AliasedWriteKept locks the alias rule: a write through a
// local pointer that was assigned from the path buffer counts as a write to the
// buffer. Without the alias set the snprintf into `p` would be invisible, the
// zero-initializer would be the only visible write, and the candidate would be
// dropped unsoundly.
func TestConstantPath_AliasedWriteKept(t *testing.T) {
	src := `#include <stdio.h>

#define BASE_DIR "/var/data"

const char *runtime_name(void);

unsigned open_dyn(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return 1;
    }
    fclose(f);
    return 0;
}

int run(void) {
    char buf[256] = {0};
    char *p = buf;
    snprintf(p, sizeof buf, "%s/%s", BASE_DIR, runtime_name());
    return (int)open_dyn(buf);
}
`
	result := setupCallsiteFixture(t, src, "path-traversal")
	if _, ok := candidatesByFunc(result)["open_dyn"]; !ok {
		t.Fatalf("open_dyn (buffer written through an alias with an unknown value) must be kept, got %v", candidateNames(result))
	}
	if len(constantPathDrops(result)) != 0 {
		t.Fatalf("an aliased write must block the proof, got %+v", constantPathDrops(result))
	}
}

// TestConstantPath_MixedCallSitesKept locks the universal quantifier: ONE
// non-constant call site keeps the candidate even when every other caller
// passes a literal. The non-constant caller is not a direct taint source (an
// unknown function result), so the taint stage leaves the decision to the
// constant-path proof.
func TestConstantPath_MixedCallSitesKept(t *testing.T) {
	src := `#include <stdio.h>

const char *runtime_name(void);

unsigned open_mixed(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return 1;
    }
    fclose(f);
    return 0;
}

int user_call(void) {
    const char *p = runtime_name();
    return (int)open_mixed(p);
}

int main(void) {
    open_mixed("/etc/fixed.conf");
    return user_call();
}
`
	result := setupCallsiteFixture(t, src, "path-traversal")
	if _, ok := candidatesByFunc(result)["open_mixed"]; !ok {
		t.Fatalf("open_mixed (one non-constant call site among literals) must be kept, got %v", candidateNames(result))
	}
	if len(constantPathDrops(result)) != 0 {
		t.Fatalf("constant_path_proof must not drop a mixed call-site parameter, got %+v", constantPathDrops(result))
	}
}
