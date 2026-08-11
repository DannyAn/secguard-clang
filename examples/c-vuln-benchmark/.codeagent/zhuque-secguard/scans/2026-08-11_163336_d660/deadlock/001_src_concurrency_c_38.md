# Deadlock in thread_deadlock_a

**CWE:** CWE-667

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/concurrency.c:38`
- **Function:** `thread_deadlock_a`

## Evidence

- **deadlock:** lock-order inversion (potential deadlock) in thread_deadlock_a at line 38

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Eliminate the lock-order inversion in `thread_deadlock_a` by establishing a consistent
global lock acquisition order:

```c
// Rule: always acquire lockA before lockB
pthread_mutex_lock(&lockA);
pthread_mutex_lock(&lockB);
// ... critical section ...
pthread_mutex_unlock(&lockB);
pthread_mutex_unlock(&lockA);
```

Document the lock hierarchy and enforce it with static analysis or
runtime lock-order sanitizers (e.g., TSan). Consider using a single
coarse-grained lock if the ordering is hard to maintain, or refactor
to avoid nested locking.
