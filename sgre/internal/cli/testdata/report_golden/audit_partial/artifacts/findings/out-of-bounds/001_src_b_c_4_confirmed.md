# Out Of Bounds in copy_all

**CWE:** CWE-125

## Location

- **File:** `<ROOT>/src/b.c:4`
- **Function:** `copy_all`
- **Variable:** `dst`

## Code Context

`<ROOT>/src/b.c:1-5` — line 4 is the reported location.

```c
  1 | #include <string.h>
  2 |
  3 | void copy_all(char *dst, const char *src) {
> 4 |     strcpy(dst, src);
  5 | }
```

## Evidence

- (no pipeline evidence package recorded for this location)

## Classification

- **Status:** confirmed (severity: low, confidence: 70%)

## Summary

strcpy may write past dst

## Reasoning

no destination size is available at the call site

## Fix Strategy

Use strlcpy with the destination capacity.
