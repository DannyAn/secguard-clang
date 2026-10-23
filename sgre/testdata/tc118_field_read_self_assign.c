/* tc118_field_read_self_assign.c — ND-02 regression: a self-referential
 * field-read reassignment (`p = p->next`) must seed a may-null source for the
 * reassigned variable (the field value is an open-world read). */
typedef struct node { int x; int y; struct node *next; } node_t;

node_t *get_node(void);

void traverse(void) {
    node_t *p = get_node();
    while (p != NULL) {
        p = p->next;
    }
}