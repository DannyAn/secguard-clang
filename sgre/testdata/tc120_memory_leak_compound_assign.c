/*
 * TC120 - Memory Leak: Compound assignment with _new-containing callee
 * ret += CLI_NewDefineCmdElement(...) uses += (compound assignment), so
 * the result of CLI_NewDefineCmdElement is used in arithmetic, not stored
 * as a pointer. Even though "_new" triggers the zero-config allocator
 * heuristic, findAllocations must skip compound assignments so no spurious
 * MEMORY_ALLOC is produced for the integer ret.
 */

int CLI_NewDefineCmdElement(int a, int b);

int tc120_compound_assign(void) {
    int ret = 0;
    ret += CLI_NewDefineCmdElement(1, 2);
    ret += CLI_NewDefineCmdElement(3, 4);
    return ret;
}