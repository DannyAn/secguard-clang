
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>


static int g_shared_counter = 0;

void *thread_race(void *arg) {

    
    for (int i = 0; i < 1000; i++) {
        g_shared_counter++;  
    }
    return NULL;
}

void demo_race_condition() {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread_race, NULL);
    pthread_create(&t2, NULL, thread_race, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    printf("Counter: %d (expected 2000)\n", g_shared_counter);
}


static pthread_mutex_t g_mutex_a = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_mutex_b = PTHREAD_MUTEX_INITIALIZER;

void *thread_deadlock_a(void *arg) {

    
    pthread_mutex_lock(&g_mutex_a);
    sleep(1);  
    pthread_mutex_lock(&g_mutex_b);  
    pthread_mutex_unlock(&g_mutex_b);
    pthread_mutex_unlock(&g_mutex_a);
    return NULL;
}

void *thread_deadlock_b(void *arg) {

    
    pthread_mutex_lock(&g_mutex_b);
    sleep(1);
    pthread_mutex_lock(&g_mutex_a);  
    pthread_mutex_unlock(&g_mutex_a);
    pthread_mutex_unlock(&g_mutex_b);
    return NULL;
}

void demo_deadlock() {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread_deadlock_a, NULL);
    pthread_create(&t2, NULL, thread_deadlock_b, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
}


static volatile int g_flag = 0;
static int g_data = 0;

void *thread_writer(void *arg) {
    g_data = 42;

    
    g_flag = 1;  
    return NULL;
}

void *thread_reader(void *arg) {

    
    if (g_flag) {  
        printf("Data: %d\n", g_data);  
    }
    return NULL;
}

void demo_data_race() {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread_writer, NULL);
    pthread_create(&t2, NULL, thread_reader, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
}


static char *g_global_ptr = NULL;


void unsafe_handler(int sig) {

    printf("Signal %d caught\n", sig);      
    free(g_global_ptr);                      
    g_global_ptr = malloc(64);               
}

void demo_unsafe_signal() {
    g_global_ptr = malloc(128);

    signal(SIGINT, unsafe_handler);
    signal(SIGTERM, unsafe_handler);
}

int main() {
    printf("Concurrency vulnerability demo\n");
    printf("Run each function individually to observe behavior:\n");
    printf("  demo_race_condition()\n");
    printf("  demo_deadlock()\n");
    printf("  demo_data_race()\n");
    printf("  demo_unsafe_signal()\n");
    return 0;
}
