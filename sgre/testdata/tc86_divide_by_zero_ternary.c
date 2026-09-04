typedef unsigned int uint32_t;

/* False branch: `(port_num == 0) ? 0 : a/port_num` — the division only runs when
 * port_num != 0, so it is safe and must not be reported. */
uint32_t ternary_false_branch_safe(uint32_t port_sum, uint32_t port_num) {
    return (port_num == 0) ? 0 : (port_sum / port_num);
}

/* True branch: `d ? a/d : 0` — the division only runs when d is truthy. */
uint32_t ternary_true_branch_safe(uint32_t a, uint32_t d) {
    return d ? (a / d) : 0;
}

/* No guard: still reported. */
uint32_t unguarded_unsafe(uint32_t a, uint32_t d) {
    return a / d;
}
