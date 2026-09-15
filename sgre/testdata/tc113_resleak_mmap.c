/* C5: mmap returns a memory mapping that must be released with munmap. The
 * resource-leak acquirer whitelist previously missed "mmap" (no "open"/"create"
 * substring), so a leaked mapping went unreported. */

void mmap_leak(unsigned long n) {
    void *m = mmap(0, n, 3, 2, -1, 0);
    (void)m;
}

void mmap_released(unsigned long n) {
    void *m = mmap(0, n, 3, 2, -1, 0);
    munmap(m, n);
}
