int div_param(int x, int d) {
    return x / d; /* d is a parameter */
}

int call_zero(int x) {
    return div_param(x, 0); /* caller passes 0 → div_param confirmed */
}

int div_param2(int x, int d) {
    return x / d;
}

int call_nonzero(int x) {
    return div_param2(x, 4); /* caller passes non-zero → div_param2 dismissed */
}

int div_param3(int x, int d) {
    return x / d;
}

int call_unknown(int x, int y) {
    return div_param3(x, y); /* caller passes variable → div_param3 suspected */
}
