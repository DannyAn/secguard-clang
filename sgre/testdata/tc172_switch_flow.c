enum Color { RED, GREEN = 3, BLUE };

void do_a(void) {}
void do_b(void) {}
void do_c(void) {}

void sf01_fallthrough(enum Color c) {
    switch (c) {
    case RED:
        do_a();
    case GREEN:
        do_b();
        break;
    default:
        break;
    }
}

void sf02_fallthrough_call(enum Color c) {
    switch (c) {
    case RED:
        do_a();
        do_b();
    case BLUE:
        do_c();
        break;
    }
}

void sf03_missing_default(enum Color c) {
    switch (c) {
    case RED:
        do_a();
        break;
    case GREEN:
        do_b();
        break;
    }
}

void sf10_comment_exempt(enum Color c) {
    switch (c) {
    case RED:
        do_a();
        /* fall through */
    case GREEN:
        do_b();
        break;
    default:
        break;
    }
}

void sf11_empty_case_chain(enum Color c) {
    switch (c) {
    case RED:
    case GREEN:
        do_b();
        break;
    default:
        break;
    }
}

void sf12_int_switch_no_default(int x) {
    switch (x) {
    case 1:
        do_a();
        break;
    case 2:
        do_b();
        break;
    }
}

void sf13_break_nested(enum Color c, int x) {
    switch (c) {
    case RED:
        switch (x) {
        case 1:
            break;
        default:
            break;
        }
        do_a();
        break;
    case GREEN:
        do_b();
        break;
    default:
        break;
    }
}

/* A brace-wrapped case body whose terminator (break/return) sits inside the
   compound block is NOT a fallthrough. */
void sf14_compound_case(enum Color c, int *out) {
    switch (c) {
    case RED: {
        *out = 1;
        break;
    }
    case GREEN: {
        *out = 2;
        return;
    }
    default:
        *out = 0;
        break;
    }
}

/* Falling into a case whose body is just `return;` is behaviorally identical to
   a break (issue #269 root cause 5.3): no statement of the next case is shared,
   so it must NOT be flagged. */
void sf15_fallthrough_into_return(int *out) {
    switch (*out) {
    case 1:
        do_a();
    default:
        return;
    }
}

/* The positive control: falling into a case that does work before returning IS
   a real fallthrough and must stay flagged. */
void sf16_fallthrough_into_work(int *out) {
    switch (*out) {
    case 1:
        do_a();
    default:
        do_b();
        return;
    }
}

int main(void) {
    enum Color c = RED;
    int out = 0;
    sf01_fallthrough(c);
    sf02_fallthrough_call(c);
    sf03_missing_default(c);
    sf10_comment_exempt(c);
    sf11_empty_case_chain(c);
    sf12_int_switch_no_default(1);
    sf13_break_nested(c, 1);
    sf14_compound_case(c, &out);
    sf15_fallthrough_into_return(&out);
    sf16_fallthrough_into_work(&out);
    return 0;
}
