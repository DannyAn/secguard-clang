
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

typedef struct {
    char  *buffer;
    size_t size;
    int    ref_count;
} AllocEntry;

static AllocEntry *g_entries[16];
static int g_entry_count = 0;


AllocEntry *alloc_entry(size_t size) {
    if (g_entry_count >= 16) return NULL;

    AllocEntry *entry = (AllocEntry *)malloc(sizeof(AllocEntry));
    if (!entry) return NULL;

    entry->buffer = (char *)malloc(size);
    if (!entry->buffer) {
        free(entry);
        return NULL;
    }

    entry->size = size;
    entry->ref_count = 1;
    g_entries[g_entry_count++] = entry;
    return entry;
}


AllocEntry *find_unused_entry() {
    for (int i = 0; i < g_entry_count; i++) {
        if (g_entries[i] && g_entries[i]->ref_count <= 0) {
            return g_entries[i];
        }
    }
    return NULL;
}


void release_entry(AllocEntry *entry) {
    if (!entry) return;

    entry->ref_count--;
    if (entry->ref_count <= 0) {
        free(entry->buffer);
        entry->buffer = NULL;
        free(entry);
    }
}


void cleanup_entries() {
    for (int i = 0; i < g_entry_count; i++) {
        if (g_entries[i]) {
            free(g_entries[i]->buffer);
            g_entries[i]->buffer = NULL;
            free(g_entries[i]);

            
            
            
        }
    }
    g_entry_count = 0;
}


void process_released_buffer() {
    AllocEntry *entry = alloc_entry(256);
    if (!entry) return;

    
    char *buf = entry->buffer;

    
    release_entry(entry);


    
    if (buf) {
        memset(buf, 0, 256);  
    }
}


int alloc_user_buffer(int user_size) {

    
    char *buf = (char *)malloc(user_size);
    assert(buf != NULL);

    memset(buf, 0, user_size);
    strcpy(buf, "initialized");
    printf("Buffer: %s\n", buf);

    free(buf);
    return 0;
}


void *alloc_objects(size_t count, size_t obj_size) {

    
    return malloc(count * obj_size);
}

int main() {
    AllocEntry *e1 = alloc_entry(128);
    AllocEntry *e2 = alloc_entry(256);

    release_entry(e1);
    release_entry(e2);

    
    AllocEntry *e3 = alloc_entry(64);
    g_entries[0] = e3;  
    cleanup_entries();    

    process_released_buffer();  
    alloc_user_buffer(1024);    
    alloc_user_buffer(2147483647);  

    return 0;
}
