/**
 * @file advanced_aes.h
 * @brief Advanced AES header file
 * @details This file contains the declaration of the functions used for AES encryption and decryption.
 * @date 2025
 */
#include "aes.h"
#include "aes_revb.h"
#include "mxc_device.h"

/**
 * @brief Set the AES key into thte AES key registers 
 * @param key Pointer to the key
 */
void aes_set_key(uint32_t* key);

/**
 *
 */
int dummy_encrypt();

int encrypt(uint32_t len, uint32_t* data, uint32_t* enc_data);

int decrypt(uint32_t len, uint32_t* enc_data, uint32_t* dec_data);
