#include <stdio.h>

typedef struct {
    char command[256];
} Task;

void format_task_desc(Task *task, const char *description) {
    sprintf(task->command, "Task[%s]", description);
}
