
#include <string.h>
#include <stddef.h>

#define MAX_MSG_SIZE 512


void copy_message(void *dst, const void *src, size_t user_len) {
    
    if (user_len > MAX_MSG_SIZE) {
        return;  
    }

    memcpy(dst, src, user_len);
                                  
                                  


    
}


void copy_to_stack_buffer(const void *src, size_t user_len) {
    char dst[256];

    if (user_len >= sizeof(dst)) {  
        return;
    }

    memcpy(dst, src, user_len);

    
}


void copy_message_unsafe(void *dst, const void *src, size_t user_len) {
    memcpy(dst, src, user_len);

    
}
