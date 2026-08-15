#include <stdlib.h>

typedef struct { int x; int y; } Point;

/* fill_point writes *p on every path, so a caller's &p is initialized. */
void fill_point(Point *p) {
    p->x = 1;
    p->y = 2;
}

int UseFilledPoint(void) {
    Point p;
    fill_point(&p);
    return p.x + p.y;
}
