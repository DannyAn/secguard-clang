struct Node {
    int value;
};

int check_node(void)
{
    struct Node *node;

    if (node != 0) {
        return node->value;
    }

    return -1;
}
