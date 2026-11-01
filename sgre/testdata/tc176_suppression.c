int suppressed_func(void) {
    int *p = 0;
    // secguard-disable-next-line: null-deref reason=external contract
    return *p;
}

int kept_func(void) {
    int *p = 0;
    return *p;
}

int main(void) {
    return suppressed_func() + kept_func();
}
