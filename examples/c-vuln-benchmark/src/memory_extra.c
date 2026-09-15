
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void heap_overflow_example(int user_len) {

    
    char *buf = (char *)malloc(user_len);  
    if (!buf) return;


    for (int i = 0; i < user_len + 10; i++) {
        buf[i] = 'A';  
    }
    free(buf);
}


int process_flag() {
    int flag;
    
    if (flag == 1) {
        return 1;
    }
    return 0;
}

typedef struct {
    int id;
    char *name;
} Record;

Record *create_record() {
    Record *r = (Record *)malloc(sizeof(Record));

    
    return r;
}


void leak_in_path(int flag) {
    char *buf = (char *)malloc(1024);
    if (!buf) return;

    if (flag) {

        
        return;  
    }

    free(buf);
}

void *allocate_and_forget() {
    char *buf = (char *)malloc(256);
    strcpy(buf, "temporary");

    
    return buf;
}


void mismatched_free_example() {

    
    char *buf = (char *)malloc(64);
    strcpy(buf, "test");


    
    
    char *dup = strdup("hello");
    free(buf);  

    
    
    
    printf("Buffer freed (mismatch depends on language context)\n");
}


void off_by_one_example() {
    char buf[64];


    
    for (int i = 0; i <= 64; i++) {
        buf[i] = 0;  
    }


    char dest[8];
    strncpy(dest, "long string", 8);
    
    int len = strlen(dest);  
    printf("Length: %d\n", len);
}


void bad_cast_example() {
    int value = 0x41424344;  



    char *str = (char *)&value;
    printf("String: %c%c%c%c\n", str[0], str[1], str[2], str[3]);  


    long large_value = 0x100000001L;
    int truncated = (int)large_value;
    printf("Truncated: %d (original: %ld)\n", truncated, large_value);
}

/* ML-03: 错误路径 return p 把指针交给调用方，正常路径从不 free —— 函数级
 * "is returned" 曾把正常路径的泄漏也吞掉（C1 回归）。 */
char *ml03_error_return_path(int err) {
    char *p = (char *)malloc(64);
    if (err) return p;
    p[0] = 'x';
    return 0;
}

/* ML-04: 覆盖指针丢分配 —— p=malloc(); p=malloc(); free(p) 释放的是第二块，
 * 第一块泄漏；ReleaseFilter 曾按 (函数,变量) 粗粒度把两个 alloc site 一起吞掉
 * （C3 回归）。 */
void ml04_overwrite_then_free(void) {
    int *p = (int *)malloc(16);
    p = (int *)malloc(32);
    free(p);
}

int main() {
    printf("Additional memory vulnerability demo\n");
    heap_overflow_example(16);
    process_flag();
    create_record();
    leak_in_path(1);
    off_by_one_example();
    bad_cast_example();
    return 0;
}
