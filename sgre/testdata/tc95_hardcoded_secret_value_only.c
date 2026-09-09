const char *high_entropy = "xJ9kL2mN8pQ4rS6tU8vW0yA3bC5dE7fG"; /* flagged by Shannon entropy */
const char *password = "admin123";                                  /* flagged by name */
const char *conn = "mysql://root:hunter2@db";                       /* flagged: URL credential */
const char *url = "https://example.com/path";                       /* NOT flagged: no credential */
const char *note = "hello world this is fine";                      /* NOT flagged: sentence */

struct cfg {
    const char *db_password;
};
struct cfg gcfg = { .db_password = "admin123" };                    /* flagged: designated initializer */

int main(void) {
    return 0;
}
