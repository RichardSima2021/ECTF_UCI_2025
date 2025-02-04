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
        "u\x89T64"\xccpF\x83\x12\xaf\x1a\xf8\x88\x11",
        "\x1e\xc2\x11\xd32\xb6\x8b[\xb0\x0e\xb1vY\x0ez2",
        "\xbf\x81\xd8\x9d\x17\x07\xbe&\x95\xf3\xe8j113`",
        "K\x119<\x08X#\xf4\xaa\x0c\x01\x90\x00\xd3\x85B",
        "r\x17\x9bp\xf0\xacs\x14\t~&9\x16eEX\xf0p\xd9\x15"
    };

    // Takes a pointer to a secret_t structure and writes it to flash memory
    write_secret(&channel_0);

    // Takes a pointer to the block of memory you want to set/clear,
    // value you want to set the memory to, and number of bytes to set to the value
    memset(&channel_0, 0, sizeof(secret_t)); // Erase SRAM


    secret_t channel_1 = {
        1,
        "\x13s\xe0xb\xfd\xe57h\xf6N\x0f\xb2-\xce#",
        "W\x9b\xf7s\x0bE5\x1bM\xaf>\xd8B\xa4\x8e\x02",
        "F\x15\xf4\xa1Q\x01(\x07e\x17R8\xdc\xc8\xcah",
        "\xc2;n\xf0\x9f\xefZ\xd63f\x0b\xdf&\xd1\x87\xde",
        "\xfca\xed\xcaw&\x17T\xbb&\xbcY\x19{8h\x13\x0c\xf7\x84"
    };

    // Takes a pointer to a secret_t structure and writes it to flash memory
    write_secret(&channel_1);

    // Takes a pointer to the block of memory you want to set/clear,
    // value you want to set the memory to, and number of bytes to set to the value
    memset(&channel_1, 0, sizeof(secret_t)); // Erase SRAM


    secret_t channel_3 = {
        3,
        "\xads\xc2\x9f9B\xd7\x02O]\x8eRh9\x9b\xf9",
        "\xceJ\xe5\xab\xd4\x87BGWEF\x02\x91E\xbd\xa6",
        "\x0c`\x04\xe9\xe0\x9b3@\x1d\xd8E\xf5\xad<^o",
        "2\xe0.Z<\x02\xe9\x9d\xbd\xac\x01\x86\xa1\x96\x0bX",
        "\xe5&07[\xe5\x84\x85\x95\xe0\x06\xf5\x0eiN|\x0c\x99\xea}"
    };

    // Takes a pointer to a secret_t structure and writes it to flash memory
    write_secret(&channel_3);

    // Takes a pointer to the block of memory you want to set/clear,
    // value you want to set the memory to, and number of bytes to set to the value
    memset(&channel_3, 0, sizeof(secret_t)); // Erase SRAM


    secret_t channel_4 = {
        4,
        "\x88\x87{\xda\xefo\xf3\xee\xf0TR\xdfh\x94S\xf4",
        "\x80\xa9k\x93=\xfbxPg\xcb\x0b\n+\x12\x90\xda",
        "<\x1c\xb5\xd9\xff\xa5\x9d\xf5\x87\xed)\x9b\t\x1a^]",
        "\xac\xa9\xe6G\xd6"\xf6\xc2:\xc1\x85\xdb\xa2\xa3\x9e\xa2",
        "O\xf0\xcdQ\xfb\xddm\xbd\xef\xfc\xfb\xf1q\xac\xbc\\\x9375;"
    };

    // Takes a pointer to a secret_t structure and writes it to flash memory
    write_secret(&channel_4);

    // Takes a pointer to the block of memory you want to set/clear,
    // value you want to set the memory to, and number of bytes to set to the value
    memset(&channel_4, 0, sizeof(secret_t)); // Erase SRAM


    // Writes the flash key to memory
    write_flash_secret("c\xe1\xd0\xe2\x8do\xe1\xe2\xdd\x0fo\xae=a\xc3\xb8");
}

#endif // SECRET_H
