int sh01_shift_over_width(int x) {
    return x << 40;
}

int sh02_shift_negative(int x) {
    return x << -1;
}

int sh03_signed_literal(void) {
    return 1 << 31;
}

unsigned sh10_unsigned_shift(unsigned u) {
    return u << 31;
}

long sh11_wide_type(long x) {
    return x << 40;
}

int sh12_var_shift(int x, int n) {
    return x << n;
}

int main(void) {
    return sh01_shift_over_width(1) + sh02_shift_negative(1) +
        sh03_signed_literal() + sh10_unsigned_shift(1) +
        sh11_wide_type(1) + sh12_var_shift(1, 3);
}
