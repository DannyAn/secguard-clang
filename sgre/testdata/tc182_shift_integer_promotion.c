/*
 * Issue #214 shape 5: shift UB must be judged on the operand's PROMOTED width.
 * A uint8_t/uint16_t operand is promoted to 32-bit int before the shift, so
 * `x << 8` / `x << 8` are legal widenings, not CWE-758. Only a count at/above
 * the promoted width (32) is undefined.
 */
#include <stdint.h>

uint32_t shift_u8_widen(uint8_t x)
{
    return (uint32_t)(x << 8);
}

uint32_t shift_u16_widen(uint16_t x)
{
    return (uint32_t)(x << 8);
}

uint32_t shift_u8_ub32(uint8_t x)
{
    return (uint32_t)(x << 32);
}

uint32_t shift_u8_ub40(uint8_t x)
{
    return (uint32_t)(x << 40);
}

uint32_t shift_u32_ub32(uint32_t x)
{
    return (uint32_t)(x << 32);
}

uint32_t shift_u64_ok(uint64_t x)
{
    return (uint32_t)(x << 40);
}
