#include <stdlib.h>
#include <string.h>

#define LOGSEND_MAX_NUM 16

typedef struct {
    void *buf[2];
} seccloud_save_entry_t;

seccloud_save_entry_t g_seccloud_save_buf[4];

void seccloud_send_list_free(void *ptr, int max_num);

void seccloud_free_save_buf(unsigned int log_type)
{
    seccloud_send_list_free(g_seccloud_save_buf[log_type].buf[0], LOGSEND_MAX_NUM);
    seccloud_send_list_free(g_seccloud_save_buf[log_type].buf[1], LOGSEND_MAX_NUM);
    memset(g_seccloud_save_buf, 0, sizeof(g_seccloud_save_buf));
}

void positive_control(void)
{
    char *p = malloc(100);
    free(p);
    free(p);
}