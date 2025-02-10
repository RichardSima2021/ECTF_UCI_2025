#ifndef RANDOM_H
#define RANDOM_H

#include <stdint.h>

#include "advanced_aes.h"
#include "advanced_flash.h"

#include "trng.h"
#include "aes.h"

/**
 * @brief Generate a random number
 * @return Random number
 */
int RandomInt(void);
/**
 * @brief  Generate a random number string with a given length into a buffer
 * @param  buf: buffer to store the random number string
 * @param  len: length of the random number string
 */
void Rand_String(uint32_t *buf, uint32_t len);
/**
 * @brief  Generate a random key with a given key size and set into aes key buffer
 * @param  keySize: key size according to AES key sizes 
 */
void generate_key(mxc_aes_keys_t keySize, uint32_t address);
/**
 * @brief  Generate random delay
 */
void Random_Delay();

#endif
