
#include <stdlib.h>
#include <string.h>
#include <pthread.h>


typedef struct {
    void *data;
    size_t size;
    int owned;  
} ResourceHandle;


ResourceHandle *ResourceHandle_create(size_t size) {
    ResourceHandle *h = (ResourceHandle *)malloc(sizeof(ResourceHandle));
    h->data = malloc(size);
    h->size = size;
    h->owned = 1;
    return h;
}


void ResourceHandle_destroy(ResourceHandle *h) {
    if (h && h->owned) {
        free(h->data);           
        h->data = NULL;
        h->owned = 0;
    }
    free(h);
}



#define ResourceHandle_scoped(name, size) \
    ResourceHandle *name = ResourceHandle_create(size); \
    int _##name##_cleanup __attribute__((cleanup(_scoped_destroy))) = 0

static void _scoped_destroy(int *flag) {
    (void)flag;  
}


void process_buffer(const void *input, size_t len) {
    ResourceHandle *handle = ResourceHandle_create(len);

    memcpy(handle->data, input, len);
                                        

    
    process_data(handle->data, handle->size);

    ResourceHandle_destroy(handle);  

    
}


void process_buffer_unsafe(const void *input, size_t len) {
    void *buf = malloc(len);
    if (!buf) return;         

    memcpy(buf, input, len);
    process_data(buf, len);
    free(buf);

    
}
