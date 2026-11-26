// CWE-478 unhandled-value switch fixtures: state machines, parse loops,
// dispatch and error-code switches where a missing (or no-op) default leaves
// downstream state stale or a loop unable to advance.

enum PktType { PKT_A, PKT_B, PKT_COUNT };
enum State { STATE_RECV, STATE_PROCESS, STATE_DONE };

int receive_packet(void) { return STATE_PROCESS; }
void process_packet(void) {}
int handle_a(void) { return 1; }
int handle_b(void) { return 2; }

// POSITIVE 1 (loop_progress): an unhandled state leaves `state` stale and the
// while loop never advances (the issue's STATE_RECV/STATE_PROCESS repro).
void fw01_state_machine_loop(void) {
    int state = STATE_RECV;
    while (state != STATE_DONE) {
        switch (state) {
        case STATE_RECV:
            state = receive_packet();
            break;
        case STATE_PROCESS:
            process_packet();
            state = STATE_RECV;
            break;
        }
    }
}

// POSITIVE 2 (loop_progress): a parse loop whose offset advances only through
// the switch — an unknown packet type leaves `pos` unchanged and the loop spins.
void fw02_parse_loop(char *buf, int len) {
    int pos = 0;
    int type;
    while (pos < len) {
        type = buf[pos];
        switch (type) {
        case 'A':
            pos += 1;
            break;
        case 'B':
            pos += 2;
            break;
        }
    }
}

// POSITIVE 3 (unhandled_state): an unhandled message type leaves `result` stale.
int md03_result_unset(int msg_type) {
    int result = 0;
    switch (msg_type) {
    case 1:
        result = handle_a();
        break;
    case 2:
        result = handle_b();
        break;
    }
    return result;
}

// POSITIVE 4 (unhandled_state): an empty `default: break;` does not handle an
// unknown state, and `next` is consumed downstream.
int md04_empty_default(int state) {
    int next = 0;
    switch (state) {
    case STATE_RECV:
        next = STATE_PROCESS;
        break;
    case STATE_PROCESS:
        next = STATE_RECV;
        break;
    default:
        break;
    }
    return next;
}

// POSITIVE 5 (unhandled_state): an error code switch whose unhandled value
// propagates into the critical path.
int md05_error_code(int rc) {
    int result = 0;
    switch (rc) {
    case 0:
        result = 1;
        break;
    case 1:
        result = -1;
        break;
    }
    return result;
}

// NEGATIVE 1: an effective default (returns an error) handles unknown values.
int md10_effective_default(int type) {
    int result = 0;
    switch (type) {
    case 1:
        result = handle_a();
        break;
    case 2:
        result = handle_b();
        break;
    default:
        return -1;
    }
    return result;
}

// NEGATIVE 2: every non-sentinel enumerator is covered (PKT_COUNT excluded), so
// no enum_gap; and there is no downstream state, so no unhandled_state either.
void md11_full_enum_covered(enum PktType t) {
    switch (t) {
    case PKT_A:
        handle_a();
        break;
    case PKT_B:
        handle_b();
        break;
    }
}

// NEGATIVE 3: the switch writes a variable, but nothing reads it afterwards.
void md12_no_downstream(int type) {
    int result;
    switch (type) {
    case 1:
        result = 1;
        break;
    case 2:
        result = 2;
        break;
    }
}

// NEGATIVE 4: a loop whose continuation does not depend on anything the switch
// updates (and the selector is not a dispatch code).
void md13_loop_unrelated(void) {
    int i = 0;
    int x = 0;
    while (i < 10) {
        switch (x) {
        case 1:
            x = 2;
            break;
        case 2:
            x = 3;
            break;
        }
        i++;
    }
}

// NEGATIVE 5: an int switch with no downstream state and a non-dispatch selector.
void md14_int_switch_no_state(int n) {
    switch (n) {
    case 1:
        handle_a();
        break;
    case 2:
        handle_b();
        break;
    }
}

int main(void) {
    char buf[4] = { 'A', 'B', 'A', 0 };
    enum PktType t = PKT_A;
    fw01_state_machine_loop();
    fw02_parse_loop(buf, 4);
    md03_result_unset(1);
    md04_empty_default(STATE_RECV);
    md05_error_code(0);
    md10_effective_default(1);
    md11_full_enum_covered(t);
    md12_no_downstream(1);
    md13_loop_unrelated();
    md14_int_switch_no_state(1);
    return 0;
}
