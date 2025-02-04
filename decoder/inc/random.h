#ifndef RANDOM_H
#define RANDOM_H

#include <stdint.h>

#include "advanced_aes.h"

#include "trng.h"
#include "aes.h"


int RandomInt(void);

void Rand_String(uint8_t *buf, uint32_t len);

void generate_key(mxc_aes_keys_t keySize);

#endif