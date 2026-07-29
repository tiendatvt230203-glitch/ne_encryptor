#ifndef CPU_MAP_H
#define CPU_MAP_H

#include <stdint.h>

static inline uint8_t ne_cpu_crypto(uint32_t worker)
{
    return (uint8_t)worker;
}

#endif
