/*
 * TC90 - Uninit: for-loop init clause initializes the loop variable.
 * Vulnerability (false positive to suppress): `xmlNodePtr child;` is declared
 * without an initializer, then `for (child = node->children; ...)` assigns it in
 * the for-init before the condition reads it. The update clause
 * `child = child->next` also reads a value that the for-init already assigned.
 * Expected: NO VALUE_USE event (child is initialized by the for-init).
 */

typedef struct _xmlNode xmlNode;
typedef xmlNode *xmlNodePtr;

int tc90_uninit_for_init(xmlNodePtr node)
{
    const char *temp_access_str = 0;
    xmlNodePtr child;
    int cnt = 0;

    for (child = node->children; child != 0; child = child->next) {
        cnt++;
    }
    return cnt;
}
