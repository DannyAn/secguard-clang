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

int main(void) {
    enum Color c = RED;
    sf01_fallthrough(c);
    sf02_fallthrough_call(c);
    sf03_missing_default(c);
    sf10_comment_exempt(c);
    sf11_empty_case_chain(c);
    sf12_int_switch_no_default(1);
    sf13_break_nested(c, 1);
    return 0;
}
