/* Cross-file typedef fixtures: the typedefs live in a HEADER so the detectors
 * must resolve them across files (they cannot be found by scanning main.c's own
 * tree alone). buildGlobalTypedefs collects them from every indexed file. */
typedef unsigned int my_uint;
typedef char *cstr_t;
