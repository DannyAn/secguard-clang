/*
 * Phase 11 — double-free (CWE-415) 覆盖缺口补全。
 *
 * 检测能力：同一变量/字段被释放两次。Detector 按 (变量, 字段) 聚合 free 站点，
 * 第二处及以后产出 DOUBLE_FREE 事件；planner 的 DoubleFreeFilter 复用 UAF 的
 * 释放态数据流（gen=首次 free，kill=重新赋值），只有首次释放能到达第二次释放时
 * 才保留；能到达且"必到达"(must) 的升为 confirmed。
 *
 * 用例：
 *   DF-01..02  expect=finding   （直接连续两次 free / 结构体字段两次 free）
 *   DF-03..04  expect=no_finding（两次 free 之间重新赋值；free 后置 NULL）
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char  *data;
    size_t len;
} DfRecord;


void df_release_twice(void) {
    char *payload = (char *)malloc(64);

    if (!payload) {
        return;
    }

    free(payload);
    free(payload);
}


void df_release_field_twice(void) {
    DfRecord *rec = (DfRecord *)malloc(sizeof(DfRecord));

    if (!rec) {
        return;
    }

    rec->data = (char *)malloc(32);
    rec->len = 32;
    if (!rec->data) {
        free(rec);
        return;
    }

    free(rec->data);
    free(rec->data);
    free(rec);
}


void df_reassign_between_frees(void) {
    char *payload = (char *)malloc(16);

    if (!payload) {
        return;
    }

    free(payload);

    payload = (char *)malloc(16);
    if (!payload) {
        return;
    }

    free(payload);
}


void df_free_null_after_release(void) {
    char *payload = (char *)malloc(16);

    if (!payload) {
        return;
    }

    free(payload);
    payload = NULL;
    free(payload);
}

int main(void) {
    df_release_twice();
    df_release_field_twice();
    df_reassign_between_frees();
    df_free_null_after_release();
    return 0;
}
