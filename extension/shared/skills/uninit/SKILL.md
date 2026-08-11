# Uninitialized Variable Analysis (CWE-457)

## Pattern
A variable is declared but used before being initialized, leading to undefined behavior.

## Detection Signals
- Local variable declared without initializer: `int x;`
- Used before first assignment: `return x;` or `arr[x]` or `if (x > 0)`
- Struct fields used before initialization

## Classification
- **confirmed**: Variable used before any assignment on all paths, function is reachable
- **suspected**: Variable may be initialized on some paths but not all (conditional init)
- **false-positive**: Variable initialized before use on all paths, or compiler enforces init

## Common False Positives
- Variable initialized via pointer (out-parameter): `init(&x)`
- Variable initialized via `memset(&x, 0, sizeof(x))`
- Variable is a struct with default-zero semantics
- Static variables (zero-initialized by C standard)