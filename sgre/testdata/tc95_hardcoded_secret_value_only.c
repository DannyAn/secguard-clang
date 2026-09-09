const char *high_entropy = "xJ9kL2mN8pQ4rS6tU8vW0yA3bC5dE7fG"; /* flagged by Shannon entropy */
const char *password = "admin123";                                  /* flagged by name */
const char *conn = "mysql://root:hunter2@db";                       /* structured URL: NOT flagged */
const char *note = "hello world this is fine";                      /* low-entropy sentence: NOT flagged */

int main(void) {
    return 0;
}
