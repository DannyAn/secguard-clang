struct cap_head { int len; int type; };

int g(void *msg) {
    struct cap_head h;
    CAP_MSG_HEAD_PARSE(msg, h); /* third-party macro, not defined here */
    return h.len;
}
