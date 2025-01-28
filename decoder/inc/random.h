#ifndef RANDOM_H
#define RANDOM_H

#include <stdint.h>
#include "trng.h"

int RandomInt(void);

void Rand_String(uint8_t *buf, uint32_t len);

#endif