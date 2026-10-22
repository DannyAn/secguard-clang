/*
 * TC151 - Memory Leak: strdup result released by a foreign-family deallocator.
 * strdup's block is paired with free() (docs §5.3: must not be mixed with
 * xmlFree*/cJSON_Delete); handing it to cJSON_Delete must NOT count as a
 * release — the string leaks.
 */

#include <stdlib.h>

typedef struct cJSON cJSON;

extern char *strdup(const char *s);
extern void cJSON_Delete(cJSON *item);

void tc151_strdup_wrong_free(const char *s) {
    char *p = strdup(s);
    if (p == NULL) return;
    cJSON_Delete((cJSON *)p);
}