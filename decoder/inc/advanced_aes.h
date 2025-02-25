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
 */
void aes_set_key();

/**
 * @brief dummy encrypt with arbitrary data
 */
int dummy_encrypt();

/** 
 * @brief Encrypt the data using AES
 * @param len Length of the data
 * @param data pointer to buffer containing data to be encrypted
 * @param enc_data pointer to buffer to store encrypted data
*/
int encrypt(uint32_t len, uint32_t* data, uint32_t* enc_data);

/**
 * @brief Decrypt the data using AES
 * @param len Length of the data
 * @param enc_data pointer to buffer containing data to be decrypted
 * @param dec_data pointer to buffer to store decrypted data
 */
int decrypt(uint32_t len, uint32_t* enc_data, uint32_t* dec_data);
