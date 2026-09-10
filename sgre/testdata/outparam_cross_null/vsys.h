#ifndef VSYS_H
#define VSYS_H

#define NULL ((void *)0)

typedef unsigned int uint32_t;
typedef unsigned short uint16_t;

typedef struct node {
    int val;
} node_t;

uint32_t get_node(node_t **out);
void caller(void);

#endif
