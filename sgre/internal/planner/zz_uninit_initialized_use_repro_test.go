//go:build !nosqlite

package planner

import "testing"

func TestUninit_InitializedPointerAndStructBranch(t *testing.T) {
	src := `#include <stdint.h>
#include <stdlib.h>

#define MID_SEC_NLOG 10
#define EPOLLIN 1
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2

typedef struct {
    uint32_t queue_max;
    uint32_t cnt;
    uint32_t len;
    void *head;
    void *tail;
    pthread_mutex_t rwlock;
} que_t;

que_t *create_queue(uint32_t max, uint32_t len)
{
    que_t *que_list = (que_t *)malloc(MID_SEC_NLOG, sizeof(que_t));
    if (que_list == NULL) {
        return NULL;
    }

    que_list->queue_max = max;
    que_list->cnt = 0;
    que_list->len = len;
    que_list->head = NULL;
    que_list->tail = NULL;
    (void)pthread_mutex_init(&(que_list->rwlock), NULL);

    return que_list;
}

typedef enum {
    DB_EPOLL_ADD_FD
} db_epoll_ctrl_type;

typedef union {
    int fd;
    void *ptr;
} epoll_data_t;

struct epoll_event {
    uint32_t events;
    epoll_data_t data;
};

extern int g_conn_fd;
extern int epoll_ctl(int, int, int, struct epoll_event *);

int32_t conn_epoll_ctrl(int32_t fd, db_epoll_ctrl_type type)
{
    int32_t ret;
    if (type == DB_EPOLL_ADD_FD) {
        struct epoll_event event;
        event.data.fd = fd;
        event.events = EPOLLIN;
        ret = epoll_ctl(g_conn_fd, EPOLL_CTL_ADD, fd, &event);
    } else {
        ret = epoll_ctl(g_conn_fd, EPOLL_CTL_DEL, fd, 0);
    }
    return ret;
}
`
	got := uninitHeapStructPlan(t, src)
	for _, fn := range []string{"create_queue", "conn_epoll_ctrl"} {
		if c, ok := got[fn+"|que_list"]; ok {
			t.Errorf("%s: false-positive candidate: var=%s line=%d level=%s", fn, c.Target.Variable, c.Target.Line, c.SuspicionLevel)
		}
		if c, ok := got[fn+"|event"]; ok {
			t.Errorf("%s: false-positive candidate: var=%s line=%d level=%s", fn, c.Target.Variable, c.Target.Line, c.SuspicionLevel)
		}
	}
}
