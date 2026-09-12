package evidence

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// TestResourceLeak_DatablockNotResource locks in the "lock"-substring fix: a
// memory allocator named allocate_new_datablock (which contains "lock" inside
// "datablock") must not be treated as a lock/resource acquirer, and the base
// variable of a field write (ll->first = ...) must not be reported as a leaked
// resource.
func TestResourceLeak_DatablockNotResource(t *testing.T) {
	store := runIndexAndDetect(t, "tc49_datablock_not_resource.c")
	assertNoEvent(t, store, "RESOURCE_ACQUIRE", "tc49_datablock_not_resource")
}

// TestResourceLeak_ErrorCodeNotResource locks in the error-code fix: an
// "Open"-named call that returns an error code (compared against UNZ_OK) must
// not be flagged, while a genuine fopen leak must still be.
func TestResourceLeak_ErrorCodeNotResource(t *testing.T) {
	store := runIndexAndDetect(t, "tc51_open_error_code.c")
	events, _ := store.ListEventsByType(context.Background(), "RESOURCE_ACQUIRE")

	flagged := make(map[string]bool)
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		flagged[props.Variable] = true
	}
	if flagged["err"] {
		t.Errorf("err (error code compared against UNZ_OK) must not be flagged as a resource, got %v", flagged)
	}
	if !flagged["f"] {
		t.Errorf("f (genuine fopen leak) should still be flagged, got %v", flagged)
	}
}

// resourceAcquireVars returns the set of variable names the resource-leak
// detector recorded as acquired resources.
func resourceAcquireVars(t *testing.T, store db.Store) map[string]bool {
	t.Helper()
	events, err := store.ListEventsByType(context.Background(), "RESOURCE_ACQUIRE")
	if err != nil {
		t.Fatalf("list RESOURCE_ACQUIRE: %v", err)
	}
	vars := make(map[string]bool, len(events))
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
		}
		if json.Unmarshal([]byte(e.Properties), &props) == nil && props.Variable != "" {
			vars[props.Variable] = true
		}
	}
	return vars
}

// TestResourceLeak_RwlockInitMallocFail pins the lock-init leak: a
// pthread_rwlock_init whose enclosing function returns on the malloc-fail branch
// without pthread_rwlock_destroy is a leaked lock resource.
func TestResourceLeak_RwlockInitMallocFail(t *testing.T) {
	store := runIndexAndDetect(t, "tc89_resleak_lock_init.c")
	vars := resourceAcquireVars(t, store)
	if !vars["g_client_registry_lock"] {
		t.Errorf("g_client_registry_lock (pthread_rwlock_init) should be flagged as an acquired resource, got %v", vars)
	}
	assertNoEvent(t, store, "RESOURCE_RELEASE", "tc89_resleak_lock_init.c")
}

// TestResourceLeak_SocketFcntlFail pins the socket leak on an fcntl-fail return:
// the socket is closed only on the success path, so the fcntl-fail branch leaks.
func TestResourceLeak_SocketFcntlFail(t *testing.T) {
	store := runIndexAndDetect(t, "tc90_resleak_socket_fcntl.c")
	vars := resourceAcquireVars(t, store)
	if !vars["socket_id"] {
		t.Errorf("socket_id (HPS_Socket) should be flagged as an acquired resource, got %v", vars)
	}
	assertNoEvent(t, store, "RESOURCE_RELEASE", "tc90_resleak_socket_fcntl.c")
}

// TestResourceLeak_EpollCreateConnectFail pins the epoll fd leak on a
// db-connect-fail return, and that a `*_sub_connect` error-code return is NOT
// mistaken for an acquired resource.
func TestResourceLeak_EpollCreateConnectFail(t *testing.T) {
	store := runIndexAndDetect(t, "tc91_resleak_epoll.c")
	vars := resourceAcquireVars(t, store)
	if !vars["g_drop_mon_epoll_fd"] {
		t.Errorf("g_drop_mon_epoll_fd (MESH_EpollCreate) should be flagged as an acquired resource, got %v", vars)
	}
	if vars["ret"] {
		t.Errorf("ret (db_create_sub_connect error code) must NOT be flagged as a resource, got %v", vars)
	}
	assertNoEvent(t, store, "RESOURCE_RELEASE", "tc91_resleak_epoll.c")
}

// TestResourceLeak_ErrorReturnFdIsLeak pins defect 1: `if (fd < 0) return fd;`
// is an error exit, not an ownership transfer, so the later unclosed fd must
// still be a leak.
func TestResourceLeak_ErrorReturnFdIsLeak(t *testing.T) {
	store := runIndexAndDetect(t, "tc92_resleak_defects.c")
	vars := resourceAcquireVars(t, store)
	if !vars["fd"] {
		t.Errorf("fd (open + error-return fd) should be flagged as an acquired resource, got %v", vars)
	}
	assertNoEvent(t, store, "RESOURCE_RELEASE", "tc92_resleak_defects.c")
}

// TestResourceLeak_DupIsLeak pins defect 2: dup() is an fd factory that must be
// recognized as an acquirer.
func TestResourceLeak_DupIsLeak(t *testing.T) {
	store := runIndexAndDetect(t, "tc92_resleak_defects.c")
	vars := resourceAcquireVars(t, store)
	if !vars["fd2"] {
		t.Errorf("fd2 (dup) should be flagged as an acquired resource, got %v", vars)
	}
}

// TestResourceLeak_OutParamAcquirerIsLeak pins defect 3: sqlite3_open(path, &db)
// writes the handle through an out-parameter and must be recognized.
func TestResourceLeak_OutParamAcquirerIsLeak(t *testing.T) {
	store := runIndexAndDetect(t, "tc92_resleak_defects.c")
	vars := resourceAcquireVars(t, store)
	if !vars["db"] {
		t.Errorf("db (sqlite3_open out-param) should be flagged as an acquired resource, got %v", vars)
	}
}

// TestResourceLeak_OverwrittenHandle locks in the lost-resource fix: `fd = open();
// fd = open();` is TWO acquisitions, and the first is lost even when the second
// is later closed (`... close(fd)` must still report one leak).
func TestResourceLeak_OverwrittenHandle(t *testing.T) {
	store := runIndexAndDetect(t, "tc111_resource_leak_overwrite.c")
	acquireByFunc, releaseByFunc := countEventsByFunction(t, store, "RESOURCE_ACQUIRE", "RESOURCE_RELEASE")

	cases := []struct {
		fn      string
		acquire int
		release int
	}{
		{"overwrite_no_close", 2, 0},
		{"overwrite_then_close", 2, 1},
	}
	for _, c := range cases {
		if acquireByFunc[c.fn] != c.acquire || releaseByFunc[c.fn] != c.release {
			t.Errorf("%s: got %d acquire / %d release, want %d acquire / %d release",
				c.fn, acquireByFunc[c.fn], releaseByFunc[c.fn], c.acquire, c.release)
		}
	}
}
