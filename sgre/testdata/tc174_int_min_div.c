int im01_const_pair(void) {
    return INT_MIN / -1;
}

int im02_assigned_const(void) {
    int x = INT_MIN;
    return x / -1;
}

int im10_var_dividend(int x) {
    return x / -1;
}

long im11_long_ctx(void) {
    return -2147483648L / -1;
}

int main(void) {
    return im01_const_pair() + im02_assigned_const() +
        im10_var_dividend(1) + (int)im11_long_ctx();
}
