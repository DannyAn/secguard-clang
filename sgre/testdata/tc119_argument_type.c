/* Contract argument-type detection fixtures (CWE-686 / CERT EXP37-C). */

#include <stdbool.h>
#include <stdint.h>

typedef unsigned int uint;

static void sink_uint(uint *p) { (void)p; }
static void sink_u32(uint32_t *p) { (void)p; }
static void sink_u64(uint64_t *p) { (void)p; }
static void sink_void(void *p) { (void)p; }
static void sink_long(long x) { (void)x; }

/* POSITIVE 1: bool object reinterpreted as uint (1 byte read as 4). */
void argtype_bool_to_uint(void)
{
    bool flag = true;
    sink_uint((uint *)&flag);
}

/* POSITIVE 2: uint32_t object read as uint64_t (4 bytes read as 8). */
void argtype_u32_to_u64(void)
{
    uint32_t x = 0;
    sink_u64((uint64_t *)&x);
}

/* NEGATIVE 1: void * boundary (no cast). */
void argtype_void_boundary(void)
{
    uint32_t x = 0;
    sink_void(&x);
}

/* NEGATIVE 2: integer promotion (no cast). */
void argtype_int_promotion(void)
{
    int x = 0;
    sink_long(x);
}

/* NEGATIVE 3: byte cast is a legal byte access. */
void argtype_byte_cast(void)
{
    uint32_t x = 0;
    sink_void((char *)&x);
}

/* NEGATIVE 4: same-size integer reinterpretation. */
void argtype_same_size_int(void)
{
    int x = 0;
    sink_uint((unsigned int *)&x);
}

/* NEGATIVE 5: identical type with a redundant cast. */
void argtype_identical_cast(void)
{
    uint x = 0;
    sink_uint((uint *)&x);
}
