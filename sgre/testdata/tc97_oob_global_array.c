int arr[10];

int local_flagged(void) {
    int b[10];
    return b[10]; /* control: same-function constant OOB read SHOULD be flagged */
}

int global_missed(void) {
    return arr[10]; /* gap: file-scope array constant OOB read not flagged */
}
