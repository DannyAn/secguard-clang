
#include <string.h>
#include <stddef.h>



typedef struct {
    void *ptr;
    size_t capacity;
} SafeBuffer;



void SafeCopy_copy(SafeBuffer *dst, const void *src, size_t n) {
    if (n > dst->capacity) {
        return;  
    }
    memcpy(dst->ptr, src, n);
                                
}


size_t SafeCopy_strcpy(SafeBuffer *dst, const char *src) {
    size_t len = strlen(src);
    if (len >= dst->capacity) {
        len = dst->capacity - 1;
    }
    memcpy(dst->ptr, src, len);
    ((char *)dst->ptr)[len] = '\0';
    return len;
}


void process_user_data(const char *user_input) {
    char buf_storage[256];
    SafeBuffer buf = {buf_storage, sizeof(buf_storage)};

    
    SafeCopy_copy(&buf, user_input, strlen(user_input));

    
}


void process_user_data_unsafe(const char *user_input) {
    char buf[64];
    memcpy(buf, user_input, strlen(user_input));

    
}
