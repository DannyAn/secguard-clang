# Resource Leak Analysis (CWE-404)

## Pattern
A resource (file descriptor, socket, database handle, lock) is acquired but not released on all execution paths.

## Detection Signals
- `open()`, `fopen()`, `socket()`, `accept()`, `connect()` → resource acquired
- `close()`, `fclose()`, `sqlite3_close()` → resource released
- Missing release in error-handling paths (early return, goto cleanup)

## Classification
- **confirmed**: Resource acquired, no release on any path, function is reachable
- **suspected**: Resource released on success path but leaked on error path
- **false-positive**: RAII pattern, goto cleanup label, or destructor always called

## Common False Positives
- `goto cleanup` patterns that close on all paths
- Wrapper classes with destructors (RAII)
- Resources passed to caller (ownership transfer)
- Process exit after acquire (OS cleans up)