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
        "EM\xf2e\xabr\xb0\x91\x05\x87Q\x14\x98\xae\xb3\r",
        ""\xb6J\xa4\xa6\xe5\r'\xb2\xa0\xa5\\)R\x82\xe5\xf4"",
        "\xb1;\xd1\xcd\xf8$\xaf\x8e\xb5!u\xb1\x16u\xf0\x03",
        "\x95\x8c?p3\xdfX\xf3Y\x19\r\xa5\x11\x0b\xfb\xd9",
        "\xda\xc2\x18DX]\xe2\xee\x89@\x0c\xd2FG\xd4\xf5\xf8w&\x12\xf4\x1b\xa3u"
    };

    // Takes a pointer to a secret_t structure and writes it to flash memory
    write_secret(&channel_0);

    // Takes a pointer to the block of memory you want to set/clear,
    // value you want to set the memory to, and number of bytes to set to the value
    memset(&channel_0, 0, sizeof(secret_t)); // Erase SRAM


    secret_t channel_1 = {
        1,
        "\xe0#|6\x84\x10\x18N\xce\xc9\x1f\xcd`q\xaf\xc0",
        "\xd0\xd7\x94\x86f\x82_\x1e\x18WP4wK0\xc8",
        ""\xc1\xf4'\xb2\x95\x0ca\xcdeQ\x18\xa4\xb8\xe4x\xad"",
        "\x8av\x03\x1d\x8f\x9c\x90\xd3vw\xef\xcd|o\x0f\xe4",
        "Jdqs\xffr\xdb\xa5\x14\xac\xbb\x90\xa7V\x7f\xa6\x9c\xfa\xd3\xddUA\xc9S"
    };

    // Takes a pointer to a secret_t structure and writes it to flash memory
    write_secret(&channel_1);

    // Takes a pointer to the block of memory you want to set/clear,
    // value you want to set the memory to, and number of bytes to set to the value
    memset(&channel_1, 0, sizeof(secret_t)); // Erase SRAM


    secret_t channel_3 = {
        3,
        ""\x87~\xb7"\x98\xe6\x1d\x03H)H\x95\xad\xdf\xd6",
        "\xa4\xccn(~\x16\xcf\xe3ORn\x19\xe3<n\xd9",
        "\xb0i\x07\xa5Oq3\xc3\x88\\\x9ac\xacx;H",
        ""\xd4\xb01s\x01\x00\x08\x18\x01R\xe4\xe9'\x00\xaf\\"",
        "p}G\x04\x90\xe3\xcb\xe6\x95k\xd2aH\xca\x9fE]r\xd6Y&a\xbf\x97"
    };

    // Takes a pointer to a secret_t structure and writes it to flash memory
    write_secret(&channel_3);

    // Takes a pointer to the block of memory you want to set/clear,
    // value you want to set the memory to, and number of bytes to set to the value
    memset(&channel_3, 0, sizeof(secret_t)); // Erase SRAM


    secret_t channel_4 = {
        4,
        "\x02R\xd6"LZ?1\x18\xd9\x1a~h\xcb\xe3f",
        "O\xd0\x00"XBm\xfb\xa3s\x84\xd1\xa2p#K",
        "\xf1j\x81\x02\xb6\xa0\xae>\xf2\xd1\x16A\xc2\x8bn*",
        "T/\x12\xdc\xafuUZ\x074\xdc\xcf\xccc\x16?",
        ";a\x8b\xc1 \xe9\xbf8\x8an\n\x96\xe5\xcc/\xac\x86\r\xb7`#\xfa!\xc2"
    };

    // Takes a pointer to a secret_t structure and writes it to flash memory
    write_secret(&channel_4);

    // Takes a pointer to the block of memory you want to set/clear,
    // value you want to set the memory to, and number of bytes to set to the value
    memset(&channel_4, 0, sizeof(secret_t)); // Erase SRAM


    // Writes the flash key to memory
    write_flash_secret("k\x9c\xb3\xfc\x9c}~H,$\x8c\xadq\xc2.\xc2");
}

#endif // SECRET_H
