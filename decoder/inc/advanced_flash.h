/**
 * @file "advanced_flash.h"
 * @author Bug Eaters
 * @brief Advanced Flash Interface Header
 * @date 2025
 */

#ifndef ADVANCED_FLASH_H
#define ADVANCED_FLASH_H

#include "flc.h"
#include "icc.h"
#include "nvic_table.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "advanced_aes.h"
#include "types.h"

//#include "simple_crypto.h"


/**
 * @brief Initialize the Flash Interface
 * 
 * This function registers the interrupt for the flash system,
 * enables the interrupt, and disables Internal Cache Controllers
*/
void flash_init(void);


/**
 * @brief Flash Advanced Read
 * 
 * @param address: uint32_t, address of flash page to read
 * @param buffer: void*, pointer to buffer for data to be read into
 * @param size: uint32_t, number of bytes to read from flash
 * @param key: char*, pointer to key to decrypt the buffer with
 * 
 * This function reads data from the specified flash page into the buffer 
 * and decrypt the buffer with the specified amount of bytes
*/
void flash_read(uint32_t address, void* buffer, uint32_t size, char* key);//need key type


/**
 * @brief Flash Advanced Write
 * @param address: uint32_t, address of flash page to write
 * @param buffer: void*, pointer to buffer to write data from
 * @param size: uint32_t, number of bytes to write from flash
 * @param key: char*, pointer to key to encrypt the buffer with
 * @return int: return negative if failure, zero if success
 * This function writes data to the specified flash page from the buffer passed
 * with the specified amount of bytes. Flash memory can only be written in one
 * way e.g. 1->0. To rewrite previously written memory see the 
 * flash_simple_erase_page documentation.
*/
int flash_write(uint32_t address, void* buffer, uint32_t size, char* key);//need key type


/**
 * @brief Flash Advanced Erase Page
 * 
 * @param address: uint32_t, address of flash page to erase
 * 
 * @return int: return negative if failure, zero if success
 * 
 * This function erases a page of flash such that it can be updated.
 * Flash memory can only be erased in a large block size called a page.
 * Once erased, memory can only be written one way e.g. 1->0.
 * In order to be re-written the entire page must be erased.
*/
int flash_erase_page(uint32_t address);

/**
 * @brief Flash Read Secrets
 * 
 * @param channel_id: int, channel id of the secret to read
 * @param buf: secret_t*, pointer to buffer for data to be read into
 * @return int: return negative if failure, zero if success
 */
int read_secrets(int channel_id, secret_t* buf);

/**
 * @brief Flash Write Secrets
 * @param s: secret_t*, pointer to secret to write
 */
void write_secrets(secret_t* s);


#endif