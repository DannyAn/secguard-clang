#define MAX 10

int arr[10];
int marr[MAX];

int local_flagged(void) {
    int b[10];
    return b[10]; /* control: same-function constant OOB read SHOULD be flagged */
}

int global_missed(void) {
    return arr[10]; /* file-scope array constant OOB read: flagged */
}

int macro_missed(void) {
    return marr[10]; /* macro-sized array constant OOB read: flagged */
}
