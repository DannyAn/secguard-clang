void pm01_chmod_literal(void) {
    chmod("/etc/app.conf", 0666);
}

void pm02_chmod_var(char *p) {
    chmod(p, 0666);
}

void pm10_tmp_path(void) {
    chmod("/tmp/app.conf", 0666);
}

void pm11_mode_var(char *p, int m) {
    chmod(p, m);
}

void pm12_readable_only(void) {
    chmod("/etc/app.conf", 0644);
}

int main(void) {
    pm01_chmod_literal();
    pm02_chmod_var((char *)0);
    pm10_tmp_path();
    pm11_mode_var((char *)0, 0);
    pm12_readable_only();
    return 0;
}
