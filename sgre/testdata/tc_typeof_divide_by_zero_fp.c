/* typeof(expr) divide-by-zero fixtures (TF-04). */

/* NEGATIVE: typeof(ratio) d = ratio (ratio is double) — the division d / n is
 * IEEE 754 float division, not an integer trap, so it must NOT be flagged. The
 * typeof specifier is parsed natively (tree-sitter-c v0.24.3 typeof_specifier);
 * its real type is not statically resolvable from the AST, so the declared
 * variable's type is treated as UNKNOWN, never as an integer. */
double f_typeof_float(double ratio, int n)
{
    typeof(ratio) d = ratio;
    return d / n;
}

/* POSITIVE control: integer division by a non-constant divisor is still flagged. */
int g_int_control(int n)
{
    int d = 5;
    return d / n;
}
