/* secret.h 
 * 
 * This header defines a secret structure (secret_t) to store various keys
 * and a checksum for different channels. The `init_secret` function 
 * initializes secret objects and writes them to flash memory.
 * 
 * Functions:
 * - write_secret: Takes a pointer to a secret_t structure and writes it to flash memory.
 * - init_secret: Initializes the secret structures for all channels.
 * - memset: Takes a pointer to the block of memory that you want to set a specific value to.
 * - write_flash_key: Writes the flash key.
*/

#ifndef SECRET_H
#define SECRET_H

#include "string.h"
#include "types.h"
#include "advanced_flash.h"

// Initializes all secret_t structs for all channels
void init_secret()
{

    secret_t channel_0 = {
        0,
        "o\xcb\xe8\xe6\x94(\xc6\xf4\x03\xff\x160\x99\xa4\x9f\xe1",
        "\xae\xbb!\x91\xfa^\x8d;\x81!\xda\x0eg\xc2hg",
        "&\xa8\xda\x14-\x89\xae\\\x9cVP\xdf4eT\xc1",
        "/X\xa0_\xed\x7f\x03\x14\x14\x1a\xc7\xf2\xf0\x0b\xee<",
        "N,\x10jrURD\x8bdu.\xc6D\xb2C(\x9b\x80\x90^\xfc6\x1d"
    };

    // Takes a pointer to a secret_t structure and writes it to flash memory
    write_secret(&channel_0);

    // Takes a pointer to the block of memory you want to set/clear,
    // value you want to set the memory to, and number of bytes to set to the value
    memset(&channel_0, 0, sizeof(secret_t)); // Erase SRAM


    secret_t channel_1 = {
        1,
        "\xa4?\xf0^\xd0\xc0\xa5\xf7\x99\xc7v\xc3\x17\xfc\xe0\x04",
        "e\xa6k\xea\x83\xb2\x8e\x0eu.\xa3\xffH\x12\x10:",
        ";\xe5F\x16\xda0i\x0b\xe1+\xab\x17c~\x8cP",
        "g\xe2}\xb8\xear\x14Q\x8e<<\xa3\xc0\x14\x85\xa5",
        "\xa1\xf1r^\xd0\xe9<.\xd6"\xb7\x10\xbd\xa2l\x0b\xe9I\xfa;\xa5\x8c\xa7V"
    };

    // Takes a pointer to a secret_t structure and writes it to flash memory
    write_secret(&channel_1);

    // Takes a pointer to the block of memory you want to set/clear,
    // value you want to set the memory to, and number of bytes to set to the value
    memset(&channel_1, 0, sizeof(secret_t)); // Erase SRAM


    secret_t channel_3 = {
        3,
        "sW\xc40Y\x85\xb8iX6\xe8\xbd(\x18&\x0c",
        "\xcd\x08\xc9\xb0\x83\xa6H\x9a.\xdd\x9a$I\xc9d\x11",
        "]\xcc,X6U\xedB{\x84\x81\xc0m\xc1\xc1i",
        "\xbeP\xf3\x98\x9ahPV\xc3\x95\xf1\xa2\xcc\xc9*\xfd",
        ""2\x98\xdb\xf8\xea>L?t\x9a\xed\x1a\xa4\x8e\x1eeje*P\x9aXA"
    };

    // Takes a pointer to a secret_t structure and writes it to flash memory
    write_secret(&channel_3);

    // Takes a pointer to the block of memory you want to set/clear,
    // value you want to set the memory to, and number of bytes to set to the value
    memset(&channel_3, 0, sizeof(secret_t)); // Erase SRAM


    secret_t channel_4 = {
        4,
        "\x8dH[\xf9\xde\x0e1\xab\xf3\xdbE\x92\xd8\xae\xdd\x8",
        ";\xe4\xf4bHf\xa0\xcaN\xdb\xe2\x11\xde;\xed\x0e",
        "\x1b:d\x9c\x80\xacX`7\x877A\xab&\xc6,",
        "\xfeg\x80\xb5>\xe7\x82\xb4\xfaJg\x1e\x9a \xbd\x1e",
        "\xe4\xc3{8\x86\xad\x168\xd7&\x03g\x1e\x86\xb7\x10\x15\xae\xb8\xcf\x92\xe6\x93\xa6"
    };

    // Takes a pointer to a secret_t structure and writes it to flash memory
    write_secret(&channel_4);

    // Takes a pointer to the block of memory you want to set/clear,
    // value you want to set the memory to, and number of bytes to set to the value
    memset(&channel_4, 0, sizeof(secret_t)); // Erase SRAM


    // Writes the flash key to memory
    write_flash_secret("HVQ_"\xab\x0e\xd1\x92\xda=\x0fr\xb41\xfc");
}

#endif // SECRET_H
