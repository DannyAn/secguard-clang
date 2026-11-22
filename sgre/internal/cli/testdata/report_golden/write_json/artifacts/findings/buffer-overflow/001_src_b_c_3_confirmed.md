# Buffer Overflow in copy_all

**CWE:** CWE-787

## Location

- **File:** `<ROOT>/src/b.c:3`
- **Function:** `copy_all`
- **Variable:** `dst`

## Code Context

`<ROOT>/src/b.c:1-5` — line 3 is the reported location.

```c
  1 | #include <string.h>
  2 |
> 3 | void copy_all(char *dst, const char *src) {
  4 |     strcpy(dst, src);
  5 | }
```

## Evidence

- (no pipeline evidence package recorded for this location)

## Classification

- **Status:** confirmed (severity: critical, confidence: 95%)

## Summary

strcpy copies an unbounded source into dst

## Reasoning

no destination capacity is checked

## Fix Strategy

Use strlcpy with sizeof(dst).
