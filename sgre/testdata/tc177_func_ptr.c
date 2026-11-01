struct file_ops {
    int (*open)(const char *);
};

int my_open(const char *p) { return *p; }

int use_ops(struct file_ops *ops, const char *p) {
    return ops->open(p);
}

void assign_ops(struct file_ops *o) {
    o->open = my_open;
}

int use_initializer(const char *p) {
    struct file_ops o = { .open = my_open };
    return o.open(p);
}

int main(void) {
    struct file_ops o;
    assign_ops(&o);
    return use_ops(&o, "x") + use_initializer("y");
}
