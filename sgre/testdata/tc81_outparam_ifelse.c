#include <stdint.h>
#include <string.h>

typedef struct { uint32_t val1; uint32_t val2; uint32_t type; } condition;

int is_valid_input(const char *t) { return t && *t; }
int is_type_a(const char *t) { return t && t[0] == 'a'; }
uint32_t get_type_a_value(const char *t, uint32_t *a, uint32_t *b) { *a = 1; *b = 2; return 0; }
uint32_t get_type_b_value(const char *t, uint32_t *a, uint32_t *b) { *a = 3; *b = 4; return 0; }

/* get_value_by_str writes *flag on BOTH branches, so a caller's &version is
 * initialized on every path. */
uint32_t get_value_by_str(const char *input, uint8_t *flag, uint32_t *out1, uint32_t *out2)
{
    if (is_type_a(input)) {
        *flag = 1;
        return get_type_a_value(input, out1, out2);
    } else {
        *flag = 0;
        return get_type_b_value(input, out1, out2);
    }
}

uint32_t process_input(const char *text, const char *type_str,
                       condition *cond, uint8_t *cond_num)
{
    if (text == NULL || strlen(text) == 0) {
        return 0;
    }

    uint32_t ret = 1;
    if (type_str == NULL || strlen(type_str) == 0) {
        if (is_valid_input(text)) {
            uint8_t version;
            ret = get_value_by_str(text, &version, &cond->val1, &cond->val2);
            cond->type = (version == 1) ? 11 : 22;
        } else {
            ret = 0;
            cond->type = 33;
        }
    }

    uint32_t type = 0;
    if (type_str != NULL && strlen(type_str) != 0) {
        if (type >= 10) {
            return 1;
        }
        if (type == 33) {
            ret = 0;
            cond->type = 33;
        } else if (is_valid_input(text)) {
            uint8_t version;
            ret = get_value_by_str(text, &version, &cond->val1, &cond->val2);
            cond->type = (version == 1) ? 11 : 22;
        }
    }

    if (ret != 0) {
        return 1;
    }

    *cond_num = *cond_num + 1;
    return 0;
}
