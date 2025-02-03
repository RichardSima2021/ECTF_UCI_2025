/**
 * @file    decoder.c
 * @author  Samuel Meyers
 * @brief   eCTF Decoder Example Design Implementation
 * @date    2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"

#include "simple_uart.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>

/* Code between this #ifdef and the subsequent #endif will
*  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
*  the projectk.mk file. */
#ifdef CRYPTO_EXAMPLE
/* The simple crypto example included with the reference design is intended
*  to be an example of how you *may* use cryptography in your design. You
*  are not limited nor required to use this interface in your design. It is
*  recommended for newer teams to start by only using the simple crypto
*  library until they have a working design. */
#include "simple_crypto.h"
#endif  //CRYPTO_EXAMPLE

/**********************************************************
 ******************* PRIMITIVE TYPES **********************
 **********************************************************/

#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t

/**********************************************************
 *********************** CONSTANTS ************************
 **********************************************************/

#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 64
#define KEY_SIZE 16
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
#define C1_LENGTH 32
// This is a canary value so we can confirm whether this decoder has booted before
#define FLASH_FIRST_BOOT 0xDEADBEEF

// These are some temperory keys for developing purposes. Need to be deleted later
#define Mask_key {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
#define Message_key {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
#define Data_key {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}

/**********************************************************
 ********************* STATE MACROS ***********************
 **********************************************************/

// Calculate the flash address where we will store channel info as the 2nd to last page available
#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))


/**********************************************************
 *********** COMMUNICATION PACKET DEFINITIONS *************
 **********************************************************/

#pragma pack(push, 1) // Tells the compiler not to pad the struct members
// for more information on what struct padding does, see:
// https://www.gnu.org/software/c-intro-and-ref/manual/html_node/Structure-Layout.html
typedef struct {
    channel_id_t channel;
    timestamp_t timestamp;
    uint8_t data[FRAME_SIZE];
} frame_packet_t;

typedef struct{
    channel_id_t channel;
    timestamp_t timestamp;
    uint8_t iv[KEY_SIZE];
    uint8_t c1[C1_LENGTH];
    uint8_t c2[FRAME_SIZE*2];
} encrypted_frame_packet_t;

typedef struct {
    decoder_id_t decoder_id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    channel_id_t channel;
} subscription_update_packet_t;

typedef struct {
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
} channel_info_t;

typedef struct {
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;

#pragma pack(pop) // Tells the compiler to resume padding struct members

/**********************************************************
 ******************** TYPE DEFINITIONS ********************
 **********************************************************/

typedef struct {
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
} channel_status_t;

typedef struct {
    uint32_t first_boot; // if set to FLASH_FIRST_BOOT, device has booted before.
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

// This is used to track decoder subscriptions
flash_entry_t decoder_status;


/**********************************************************
 ******************* UTILITY FUNCTIONS ********************
 **********************************************************/

/** @brief Checks whether the decoder is subscribed to a given channel
 *
 *  @param channel The channel number to be checked.
 *  @return 1 if the the decoder is subscribed to the channel.  0 if not.
*/
int is_subscribed(channel_id_t channel) {
    // Check if this is an emergency broadcast message
    if (channel == EMERGENCY_CHANNEL) {
        return 1;
    }
    // Check if the decoder has has a subscription
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == channel && decoder_status.subscribed_channels[i].active) {
            return 1;
        }
    }
    return 0;
}



int xorArrays(uint8_t *arr1, uint8_t *arr2, size_t arr1_len, size_t arr2_len, u_int8_t* result) {

    // Check if input arrays are valid
    if (arr1 == NULL || arr2 == NULL || result == NULL) {
        fprintf(stderr, "Error: Invalid input arrays.\n");
        return -1;
    }

    for (size_t i = 0; i < 16; i++) {
        uint8_t byte1 = (i < arr1_len) ? arr1[i] : 0x00; // Use 0x00 if arr1 is shorter
        uint8_t byte2 = (i < arr2_len) ? arr2[i] : 0x00; // Use 0x00 if arr2 is shorter
        result[i] = byte1 ^ byte2;
    }  

    return 0;   
}

void compute_hash(const unsigned char *data, size_t length, unsigned char *hash) {
    wc_Sha256 sha256;

    if (wc_InitSha256(&sha256) != 0) {
        fprintf(stderr, "Failed to initialize SHA-256 context!\n");
        return; 
    }

    if (wc_Sha256Update(&sha256, data, length) != 0) {
        fprintf(stderr, "Failed to update SHA-256 hash!\n");
        wc_Sha256Free(&sha256);
        return; 
    }

    unsigned char full_hash[WC_SHA256_DIGEST_SIZE];
    if (wc_Sha256Final(&sha256, full_hash) != 0) {
        fprintf(stderr, "Failed to finalize SHA-256 hash!\n");
        wc_Sha256Free(&sha256);
        return; 
    }

    memcpy(hash, full_hash, 16);

    wc_Sha256Free(&sha256);
}

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Lists out the actively subscribed channels over UART.
 *
 *  @return 0 if successful.
*/
int list_channels() {
    list_response_t resp;
    pkt_len_t len;

    resp.n_channels = 0;

    for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active) {
            resp.channel_info[resp.n_channels].channel =  decoder_status.subscribed_channels[i].id;
            resp.channel_info[resp.n_channels].start = decoder_status.subscribed_channels[i].start_timestamp;
            resp.channel_info[resp.n_channels].end = decoder_status.subscribed_channels[i].end_timestamp;
            resp.n_channels++;
        }
    }

    len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);

    // Success message
    write_packet(LIST_MSG, &resp, len);
    return 0;
}


/** @brief Updates the channel subscription for a subset of channels.
 *
 *  @param pkt_len The length of the incoming packet
 *  @param update A pointer to an array of channel_update structs,
 *      which contains the channel number, start, and end timestamps
 *      for each channel being updated.
 *
 *  @note Take care to note that this system is little endian.
 *
 *  @return 0 upon success.  -1 if error.
*/
int update_subscription(pkt_len_t pkt_len, subscription_update_packet_t *update) {
    int i;

    if (update->channel == EMERGENCY_CHANNEL) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
        return -1;
    }

    // Find the first empty slot in the subscription array
    for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == update->channel || !decoder_status.subscribed_channels[i].active) {
            decoder_status.subscribed_channels[i].active = true;
            decoder_status.subscribed_channels[i].id = update->channel;
            decoder_status.subscribed_channels[i].start_timestamp = update->start_timestamp;
            decoder_status.subscribed_channels[i].end_timestamp = update->end_timestamp;
            break;
        }
    }

    // If we do not have any room for more subscriptions
    if (i == MAX_CHANNEL_COUNT) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - max subscriptions installed\n");
        return -1;
    }

    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    // Success message with an empty body
    write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}

/** @brief Processes a packet containing frame data.
 *
 *  @param pkt_len A pointer to the incoming packet.
 *  @param new_frame A pointer to the incoming packet.
 *
 *  @return 0 if successful.  -1 if data is from unsubscribed channel.
*/
int decode(pkt_len_t pkt_len, encrypted_frame_packet_t *new_frame) {
    char output_buf[128] = {0};
    uint16_t frame_size;
    channel_id_t channel;
    timestamp_t timestamp;


    // Get the plain text info from the encrypted frame
    channel = new_frame->channel;
    timestamp = new_frame->timestamp;

    // Todo: Decrypt c1 and c2, and validate timestamps

    // Decrypt c1 first
    uint8_t ts_prime[24];
    uint8_t nonce[16];
    uint8_t frame_data[64]; // Assuming max frame size is 64 bytes
    uint8_t mask_key[KEY_SIZE] = Mask_key;
    uint8_t message_key[KEY_SIZE] = Message_key;
    uint8_t data_key[KEY_SIZE] = Data_key;

    // Load keys (replace with your key loading logic)
    
    // Construct the key for c1
    // XOR mask key with the timestamp
    uint8_t c1_key[KEY_SIZE] = {0};
    memcpy(c1_key, &timestamp, sizeof(timestamp));
    xorArrays(c1_key, mask_key, c1_key, KEY_SIZE);
    // Hash the the XOR result from the previous step
    compute_hash(c1_key, KEY_SIZE, c1_key);

    // XOR the hash result with message key to get the decryption key for c1
    xorArrays(c1_key, message_key, c1_key, KEY_SIZE);

    // Decrypt c1 with the decryption key and get timestamp prime
    decrypt_sym(new_frame->c1, C1_LENGTH, c1_key, new_frame->iv, ts_prime);

    // Extract nonce from timestamp prime
    memcpy(nonce, ts_prime, 8);
    memcpy(nonce + 8, ts_prime + 16, 8);


    // Start to decrypt c2
    // Construct the key for c2
    // XOR data key with the nounce to get the decryption key for c2
    uint8_t c2_key[KEY_SIZE] = {0};
    xorArrays(nonce, data_key, c2_key, KEY_SIZE);

    // Calculate the length of c2
    int c2_length = pkt_len - sizeof(channel_id_t) - sizeof(timestamp_t) - KEY_SIZE - C1_LENGTH;

    // Decrypt c2 with the decryption key and get the frame data
    decrypt_sym(new_frame->c2, c2_length, c2_key, new_frame->iv, frame_data);
    

    // Check that we are subscribed to the channel...
    print_debug("Checking subscription\n");
    if (is_subscribed(channel)) {
        print_debug("Subscription Valid\n");
        /* The reference design doesn't need any extra work to decode, but your design likely will.
        *  Do any extra decoding here before returning the result to the host. */
        write_packet(DECODE_MSG, frame_data, sizeof(frame_data));
        return 0;
    } else {
        STATUS_LED_RED();
        sprintf(
            output_buf,
            "Receiving unsubscribed channel data.  %u\n", channel);
        print_error(output_buf);
        return -1;
    }
}

/** @brief Initializes peripherals for system boot.
*/
void init() {
    int ret;

    // Initialize the flash peripheral to enable access to persistent memory
    flash_simple_init();

    // Read starting flash values into our flash status struct
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        /* If this is the first boot of this decoder, mark all channels as unsubscribed.
        *  This data will be persistent across reboots of the decoder. Whenever the decoder
        *  processes a subscription update, this data will be updated.
        */
        print_debug("First boot.  Setting flash...\n");

        decoder_status.first_boot = FLASH_FIRST_BOOT;

        channel_status_t subscription[MAX_CHANNEL_COUNT];

        for (int i = 0; i < MAX_CHANNEL_COUNT; i++){
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;
        }

        // Write the starting channel subscriptions into flash.
        memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT*sizeof(channel_status_t));

        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }

    // Initialize the uart peripheral to enable serial I/O
    ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        // if uart fails to initialize, do not continue to execute
        while (1);
    }
}

/* Code between this #ifdef and the subsequent #endif will
*  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
*  the projectk.mk file. */
#ifdef CRYPTO_EXAMPLE
void crypto_example(void) {
    // Example of how to utilize included simple_crypto.h

    // This string is 16 bytes long including null terminator
    // This is the block size of included symmetric encryption
    // char *data = "Crypto Example!";
    // uint8_t ciphertext[BLOCK_SIZE];
    // uint8_t key[KEY_SIZE];
    // uint8_t hash_out[HASH_SIZE];
    // uint8_t decrypted[BLOCK_SIZE];

    // char output_buf[128] = {0};

    // // Zero out the key
    // bzero(key, BLOCK_SIZE);

    // // Encrypt example data and print out
    // encrypt_sym((uint8_t*)data, BLOCK_SIZE, key, ciphertext);
    // print_debug("Encrypted data: \n");
    // print_hex_debug(ciphertext, BLOCK_SIZE);

    // // Hash example encryption results
    // hash(ciphertext, BLOCK_SIZE, hash_out);

    // // Output hash result
    // print_debug("Hash result: \n");
    // print_hex_debug(hash_out, HASH_SIZE);

    // // Decrypt the encrypted message and print out
    // decrypt_sym(ciphertext, BLOCK_SIZE, key, decrypted);
    // sprintf(output_buf, "Decrypted message: %s\n", decrypted);
    // print_debug(output_buf);
}
#endif  //CRYPTO_EXAMPLE

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void) {
    char output_buf[128] = {0};
    uint8_t uart_buf[100];
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // initialize the device
    init();

    print_debug("Decoder Booted!\n");

    #ifdef CRYPTO_EXAMPLE

    // print_debug("\n\nCrypto Example\n");

    // uint8_t ciphertext[BLOCK_SIZE] = "Hello, World!";
    // uint8_t key[KEY_SIZE];
    // uint8_t decrypted[BLOCK_SIZE];
    // decrypt_sym(ciphertext, BLOCK_SIZE, key, decrypted);
    // print_debug(decrypted);

    // print_debug("\n\n");

    crypto_example();

    #endif

    // process commands forever
    while (1) {
        print_debug("Ready\n");

        STATUS_LED_GREEN();

        result = read_packet(&cmd, uart_buf, &pkt_len);

        if (result < 0) {
            STATUS_LED_ERROR();
            print_error("Failed to receive cmd from host\n");
            continue;
        }

        // Handle the requested command
        switch (cmd) {

        // Handle list command
        case LIST_MSG:
            STATUS_LED_CYAN();

            #ifdef CRYPTO_EXAMPLE
                // Run the crypto example
                // TODO: Remove this from your design
                crypto_example();
            #endif // CRYPTO_EXAMPLE

            // Print the boot flag
            // TODO: Remove this from your design
            boot_flag();
            list_channels();
            break;

        // Handle decode command
        case DECODE_MSG:
            STATUS_LED_PURPLE();
            decode(pkt_len, (encrypted_frame_packet_t *)uart_buf);
            break;

        // Handle subscribe command
        case SUBSCRIBE_MSG:
            STATUS_LED_YELLOW();
            update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
            break;

        // Handle bad command
        default:
            STATUS_LED_ERROR();
            sprintf(output_buf, "Invalid Command: %c\n", cmd);
            print_error(output_buf);
            break;
        }
    }
}
