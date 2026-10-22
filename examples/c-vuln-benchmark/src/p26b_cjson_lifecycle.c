/*
 * Phase 26b — cJSON lifecycle semantics (user-provided canonical forms):
 * the standard create/attach/print/release flow, the borrowed-item misuse,
 * and the Detach ownership move. Get vs Detach vs AddItemReference carry
 * three DIFFERENT ownership rules; these cases lock them end-to-end.
 */

#include <stdio.h>
#include <stdlib.h>

typedef struct cJSON { int valueint; struct cJSON *child; } cJSON;

extern cJSON *cJSON_CreateObject(void);
extern cJSON *cJSON_CreateString(const char *s);
extern int cJSON_AddItemToObject(cJSON *obj, const char *key, cJSON *item);
extern char *cJSON_PrintUnformatted(const cJSON *item);
extern void cJSON_free(void *p);
extern void cJSON_Delete(cJSON *item);
extern cJSON *cJSON_Parse(const char *value);
extern cJSON *cJSON_GetObjectItem(const cJSON *obj, const char *key);
extern cJSON *cJSON_DetachItemFromObject(cJSON *obj, const char *key);

/* P26-09 (no_finding): the canonical create → attach (failure branch
 * deletes) → print → cJSON_free(json) → cJSON_Delete(root) flow. All three
 * ownership rules correctly exercised. */
int main(void)
{
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return 1;
    }

    cJSON *name = cJSON_CreateString("Alice");
    if (name == NULL) {
        cJSON_Delete(root);
        return 1;
    }

    if (!cJSON_AddItemToObject(root, "name", name)) {
        cJSON_Delete(name);
        cJSON_Delete(root);
        return 1;
    }

    char *json = cJSON_PrintUnformatted(root);
    if (json == NULL) {
        cJSON_Delete(root);
        return 1;
    }

    puts(json);

    cJSON_free(json);
    cJSON_Delete(root);

    return 0;
}

/* P26-10 (suspected-tier candidate, NOT in validator ground truth): the
 * borrowed item from cJSON_GetObjectItem is deleted on its own — an invalid
 * free (UAF/double-free when the root is deleted later). Surfaced as a
 * free-on-borrow candidate for the AI; locked by the evidence unit tests
 * (tc160) instead of the SARIF validator. */
void p26_delete_borrowed_item(const char *value) {
    cJSON *root = cJSON_Parse(value);
    if (root == NULL) {
        return;
    }

    cJSON *name = cJSON_GetObjectItem(root, "name");

    /* 错误：name 是 root 内部的借用指针 */
    cJSON_Delete(name);

    cJSON_Delete(root);
}

/* P26-11 (no_finding): Detach hands the item's ownership to the caller,
 * which deletes it; the root is deleted separately. Both chains paired. */
void p26_detach_ok(const char *value) {
    cJSON *root = cJSON_Parse(value);
    if (root == NULL) {
        return;
    }

    cJSON *name = cJSON_DetachItemFromObject(root, "name");
    if (name != NULL) {
        cJSON_Delete(name);
    }

    cJSON_Delete(root);
}

/* P26-12 (finding): the detached item is caller-owned and never deleted —
 * a definite leak (the root's cJSON_Delete no longer covers it). */
void p26_detach_leak(const char *value) {
    cJSON *root = cJSON_Parse(value);
    if (root == NULL) {
        return;
    }

    cJSON *name = cJSON_DetachItemFromObject(root, "name");
    if (name == NULL) {
        cJSON_Delete(root);
        return;
    }

    cJSON_Delete(root);
}