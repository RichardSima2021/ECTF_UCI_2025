#ifndef RANDOM_H
#define RANDOM_H

#include <stdint.h>

#include "advanced_aes.h"

#include "trng.h"
#include "aes.h"

/**
 * @brief Generate a random number using TRNG on the board
 * @return Random number
 */
int RandomInt(void);

/**
 * @brief Generate a random string using TRNG on the board
 * @param buf Buffer to store the random string
 * @param len Length of the random string
 */
void Rand_String(uint8_t *buf, uint32_t len);

/**
 * @brief Generate a random key using TRNG
 * @param keySize Size of the key
 */
void generate_key(mxc_aes_keys_t keySize);

#endif