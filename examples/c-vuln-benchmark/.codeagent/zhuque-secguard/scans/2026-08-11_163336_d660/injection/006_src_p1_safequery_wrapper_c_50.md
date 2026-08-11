# Injection in lookup_user_unsafe

**CWE:** CWE-78

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/p1_safequery_wrapper.c:50`
- **Function:** `lookup_user_unsafe`
- **Variable:** `sqlite3_exec(db, query, NULL, NULL, NULL)`

## Evidence

- **unsafe_call:** unsafe function call in lookup_user_unsafe at line 50
- **call_path:** function lookup_user_unsafe is reachable from entry

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Use parameterized queries instead of string concatenation in `lookup_user_unsafe`:

```c
sqlite3_stmt *stmt;
sqlite3_prepare_v2(db, "SELECT * FROM t WHERE id = ?", -1, &stmt, NULL);
sqlite3_bind_text(stmt, 1, user_input, -1, SQLITE_STATIC);
sqlite3_step(stmt);
sqlite3_finalize(stmt);
```

Never interpolate user-controlled data into SQL query strings.
