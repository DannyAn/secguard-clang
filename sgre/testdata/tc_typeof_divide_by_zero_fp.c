/* typeof(expr) divide-by-zero fixtures (TF-04). */

/* NEGATIVE: typeof(ratio) d = ratio (ratio is double) — the division d / n is
 * IEEE 754 float division, not an integer trap, so it must NOT be flagged. The
 * typeof rewrite masks d's type to void *, which must be treated as UNKNOWN,
 * never as an integer. */
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
