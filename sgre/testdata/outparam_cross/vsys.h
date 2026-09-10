#ifndef VSYS_H
#define VSYS_H

#define NULL ((void *)0)

typedef unsigned int uint32_t;
typedef unsigned short uint16_t;

uint32_t vsys_get_vsysid_by_vrfindex(uint16_t vrfindex, uint16_t *vsysid);

#endif
