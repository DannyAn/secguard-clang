#include <stdlib.h>
#include <string.h>

typedef unsigned int uint32_t;

#define LOGSEND_MAX_NUM 16

typedef struct {
    char *json_str;
    int len;
} seccloud_json_t;

typedef struct {
    seccloud_json_t *buf[2];
} seccloud_save_entry_t;

seccloud_save_entry_t g_seccloud_save_buf[4];

void cJSON_free(void *ptr)
{
    free(ptr);
}

void seccloud_send_item_free(seccloud_json_t *ptr)
{
    if (ptr == NULL) {
        return;
    }
    if (ptr->json_str == NULL) {
        return;
    }
    cJSON_free(ptr->json_str);
    ptr->len = 0;
    ptr->json_str = NULL;
}

void seccloud_send_list_free(seccloud_json_t *list, uint32_t num)
{
    for (int i = 0; i < num; i++) {
        seccloud_send_item_free(&list[i]);
    }
}

void seccloud_free_save_buf(uint32_t log_type)
{
    seccloud_send_list_free(g_seccloud_save_buf[log_type].buf[0], LOGSEND_MAX_NUM);
    seccloud_send_list_free(g_seccloud_save_buf[log_type].buf[1], LOGSEND_MAX_NUM);
    memset_s(g_seccloud_save_buf, sizeof(g_seccloud_save_buf), 0, sizeof(g_seccloud_save_buf));
}

void positive_control(void)
{
    char *p = malloc(100);
    free(p);
    free(p);
}
