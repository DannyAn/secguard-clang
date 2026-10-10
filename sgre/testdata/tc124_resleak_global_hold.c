/*
 * TC124 - Resource Leak: a resource held in a global/static variable is
 * process-lifetime state, not a leak, and must NOT be auto-confirmed.
 *
 * iconv_open / dlopen / epoll_create results stored into globals (and a static
 * function-local cache) are reused for the process lifetime, so the detector
 * must not mark them definite. They stay suspected for the AI (P0-2).
 */

typedef struct { int h; } iconv_t;
typedef void *dlhandle_t;

static iconv_t iconv_open(const char *a, const char *b) { (void)a; (void)b; iconv_t r; r.h = 1; return r; }
static void *dlopen(const char *p, int f) { (void)p; (void)f; return (void *)1; }
static int epoll_create(int n) { (void)n; return 5; }

static iconv_t g_handler_gbk_to_utf8;
static dlhandle_t g_plugin_handle;
static int g_epoll_fd;

void init_handlers(void) {
    if (g_handler_gbk_to_utf8.h == 0) {
        g_handler_gbk_to_utf8 = iconv_open("UTF-8", "GBK");
    }
    g_plugin_handle = dlopen("plugin.so", 2);
    g_epoll_fd = epoll_create(16);
}

void load_once(void) {
    static int cached_fd = -1;
    if (cached_fd < 0) {
        cached_fd = epoll_create(8);
    }
}
