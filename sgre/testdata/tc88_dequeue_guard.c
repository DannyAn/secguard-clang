typedef unsigned int uint32_t;

#define sample_OK 0
#define sample_ERR 1

typedef struct {
    uint32_t is_active;
    char *param;
} sample_alarm_message;

int queue_empty(void);
char *get_param(void);
void use_field(char *p);

/* Writes *out only on the success path (returns sample_OK). */
int sample_alarm_dequeue(sample_alarm_message *out) {
    if (queue_empty()) {
        return sample_ERR;
    }
    out->is_active = 1;
    out->param = get_param();
    return sample_OK;
}

/* The caller guards the conditional write with `while (dequeue(&msg) == OK)`;
 * the body runs only on the success path, so msg.param IS written. */
void process_queue(void) {
    sample_alarm_message msg;
    while (sample_alarm_dequeue(&msg) == sample_OK) {
        use_field(msg.param);
    }
}

/* No return check: the conditional write may not have happened, so msg.param
 * may be unwritten — this stays reported. */
void unguarded(void) {
    sample_alarm_message bad_msg;
    sample_alarm_dequeue(&bad_msg);
    use_field(bad_msg.param);
}
