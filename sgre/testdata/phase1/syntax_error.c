/* syntax_error.c - intentional syntax error + 1 valid function */
#include <stdlib.h>

int valid_function(void) {
    return 42;
}

/* syntax error: missing semicolon and brace */
int broken_function( {
    return 0
}