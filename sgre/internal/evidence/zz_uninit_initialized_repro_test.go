//go:build !nosqlite

package evidence

import "testing"

func TestUninit_InitializedPointerAndStructBranchNoValueUse(t *testing.T) {
	src := `typedef unsigned int uint32_t;
typedef struct {
    uint32_t queue_max;
    uint32_t cnt;
    uint32_t len;
    void *head;
    void *tail;
    int rwlock;
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

int32_t conn_epoll_ctrl(int32_t fd, db_epoll_ctrl_type type)
{
    int32_t ret;
    if (type == DB_EPOLL_ADD_FD) {
        struct epoll_event event;
        event.data.fd = fd;
        event.events = EPOLLIN;
        ret = epoll_ctl(0, 1, fd, &event);
    } else {
        ret = epoll_ctl(0, 2, fd, 0);
    }
    return ret;
}
`
	uses := runUninitInline(t, src)
	for _, u := range uses {
		if u.function == "create_queue" || u.function == "conn_epoll_ctrl" {
			t.Errorf("false-positive VALUE_USE: function=%s variable=%s origin=%s line=%d", u.function, u.variable, u.origin, u.line)
		}
	}
}
