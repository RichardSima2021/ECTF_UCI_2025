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
#include "advanced_flash.h"
#include "host_messaging.h"
#include "types.h"

#include "simple_uart.h"


// /* Code between this #ifdef and the subsequent #endif will
// *  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
// *  the projectk.mk file. */
#ifdef CRYPTO_EXAMPLE
// /* The simple crypto example included with the reference design is intended
// *  to be an example of how you *may* use cryptography in your design. You
// *  are not limited nor required to use this interface in your design. It is
// *  recommended for newer teams to start by only using the simple crypto
// *  library until they have a working design. */
#include "simple_crypto.h"
#endif  //CRYPTO_EXAMPLE



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


/** @brief Extracts subscription information and checksum from interwoven message.
 * 
 *  @param intrwvn_msg A pointer to the beginning of our interwoven subscription information
 *  @param subscription_info A pointer to the output of the extracted subscription information
 *  @param checksum A pointer to the output of the extracted checksum
 * 
 *  @return 0 upon success. -1 if error
 */
int extract(interwoven_bytes *intrwvn_msg, subscription_update_packet_t *subscription_info, unsigned char *checksum) {
    // Validate intrwvn_msg/output pointers
    // (Nest for glitch protection)
    if (intrwvn_msg == NULL) return -1;
    if (subscription_info == NULL) return -1;
    if (checksum == NULL) return -1;


    // Expecting 48 bytes from interwoven message
    // 20 bytes for the subscription info (device ID, start timestamp, end timestamp)
    // 20 bytes for the checksum
    // 8 bytes for padding (Junk, ignore)

    /*
        Questions:
            Another security issue:
                - As it stands, arguments fed into this function are to be
                  staticly allocated character arrays stored in stack.
                  Is this safe?
    */

    char temp_subscription_arr[20];

    // Extract the interwoven message into their respective character arrays
    for (int i = 0; i < 40; i++) {
        if (i % 2 == 0) {
            temp_subscription_arr[i / 2] = intrwvn_msg[i];
        }
        else {
            checksum[i / 2] = intrwvn_msg[i];
        }
    }

    // Null-terminate the output strings
    temp_subscription_arr[20] = '\0';
    checksum[20] = '\0';

    // Copy the temporary subscription array into the subscription_info struct
    /*
        timestamp_t uint64_t
        decoder_id_t uint32_t

        | decoder_id  | start_timestamp | end_timestamp  |
        |   4 bytes   |     8 bytes     |    8 bytes     |
    */

    // Pull individual values from temp_subscription_arr
    subscription_info->decoder_id = (temp_subscription_arr[0] - '0') * 1000 + (temp_subscription_arr[1] - '0') * 100 + (temp_subscription_arr[2] - '0') * 10 + (temp_subscription_arr[3] - '0');
    subscription_info->start_timestamp = (temp_subscription_arr[4] - '0') * 10000000 + (temp_subscription_arr[5] - '0') * 1000000 + (temp_subscription_arr[6] - '0') * 100000 + (temp_subscription_arr[7] - '0') * 10000 + (temp_subscription_arr[8] - '0') * 1000 + (temp_subscription_arr[9] - '0') * 100 + (temp_subscription_arr[10] - '0') * 10 + (temp_subscription_arr[11] - '0');
    subscription_info->end_timestamp = (temp_subscription_arr[12] - '0') * 10000000 + (temp_subscription_arr[13] - '0') * 1000000 + (temp_subscription_arr[14] - '0') * 100000 + (temp_subscription_arr[15] - '0') * 10000 + (temp_subscription_arr[16] - '0') * 1000 + (temp_subscription_arr[17] - '0') * 100 + (temp_subscription_arr[18] - '0') * 10 + (temp_subscription_arr[19] - '0');
    
    return 0;  // Success
}



/** @brief Helper function to reset the channel info in subscribed_channels at index i
 * 
 *  @param i the index at which to reset channel info
 * 
*/
void reset_channel(int i) {
    decoder_status.subscribed_channels[i].id = DEFAULT_CHANNEL_ID;
    decoder_status.subscribed_channels[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
    decoder_status.subscribed_channels[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
    decoder_status.subscribed_channels[i].active = false;
}

/** @brief Helper function to check if duplicate channel ids exist which are active
 * 
 *  @note Should always return false
 * 
 *  @return 0 upon none found, 1 if found duplicate
*/
bool found_duplicate_channel_id() {
    int i;
    int j;
    for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
        for (j = 0; j < MAX_CHANNEL_COUNT; j++) {
            if (i != j) {
                if (decoder_status.subscribed_channels[i].id == decoder_status.subscribed_channels[j].id && decoder_status.subscribed_channels[i].active && decoder_status.subscribed_channels[j].active) {
                    return -1;
                }
            }
        }
    }
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
//                                         this update info will be updated later to be encoded input
int update_subscription(pkt_len_t pkt_len, encrypted_update_packet *packet) {
    /*   
    2. Update subscription 
        1. Extract first four bytes to get channel ID
        1.5. Extract rest of encrypted interwoven bytestring
        2. Retrieve secrets from flash to find channel with given ID
        3. Use subscription key from corresponding secret_t to decrypt packet
        4. De-interweave to get concatenated sub info
        5. Extract sub info
        6. Update sub info
    */

    channel_id_t channel_id;
    secret_t *channel_secrets;
    interwoven_bytes *interwoven_encrypted;
    interwoven_bytes *interwoven_decrypted;


    // encrypted_packet = channel_id (4 bytes) + ciphertext
    //      ciphertext  = 48 bytes interweaved

    // 1.
    memcpy(&channel_id, packet->encrypted_packet, sizeof(channel_id_t));
    // 1.5
    memcpy(&interwoven_encrypted, packet->encrypted_packet + sizeof(channel_id_t), sizeof(interwoven_encrypted));

    // 2.
    read_secrets(channel_id, channel_secrets);

    // 3.
    decrypt_sym(&interwoven_encrypted, 48, channel_secrets->subscription_key, &interwoven_decrypted);

    // 4. & 5.
    subscription_update_packet_t *update;
    update->channel = channel_id;

    unsigned char checksum [20];

    if (extract(interwoven_decrypted, update, checksum) != 0) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - could not update subscription\n");
        return -1;
    }
    

    // 6.
    int i;

    if (update->channel == EMERGENCY_CHANNEL) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
        return -1;
    }

    bool modified = false;
    // Find the first empty slot in the subscription array
    for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
        
        // if this channel is the same ID as incoming channel info or it's not an active channel
        if (decoder_status.subscribed_channels[i].id == update->channel || !decoder_status.subscribed_channels[i].active) {
            // already performed modification && found duplicate channel id
            if (modified && decoder_status.subscribed_channels[i].id == update->channel) {
                reset_channel(i);
            }
            // already performed modification and found inactive channel 
            else if (modified) {
                // don't do anything
                continue;
            }
            // have not performed update
            else {
                // set channel status to true
                decoder_status.subscribed_channels[i].active = true;
                // set channel id to incoming id
                decoder_status.subscribed_channels[i].id = update->channel;
                // set start timestamp
                decoder_status.subscribed_channels[i].start_timestamp = update->start_timestamp;
                // set end timestamp
                decoder_status.subscribed_channels[i].end_timestamp = update->end_timestamp;
                modified = true;
            }
            
        }
    }


    // If we find duplicate channel ids (this should not happen)
    if (found_duplicate_channel_id()) {
        STATUS_LED_RED();
        print_error("Channel list should not contain duplicates\n");
        return -1;
    }

    flash_erase_page(FLASH_STATUS_ADDR);
    flash_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t), "");
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
int decode(pkt_len_t pkt_len, frame_packet_t *new_frame) {
    char output_buf[128] = {0};
    uint16_t frame_size;
    channel_id_t channel;

    // Frame size is the size of the packet minus the size of non-frame elements
    frame_size = pkt_len - (sizeof(new_frame->channel) + sizeof(new_frame->timestamp));
    channel = new_frame->channel;

    // The reference design doesn't use the timestamp, but you may want to in your design
    // timestamp_t timestamp = new_frame->timestamp;

    // Check that we are subscribed to the channel...
    print_debug("Checking subscription\n");
    if (is_subscribed(channel)) {
        print_debug("Subscription Valid\n");
        /* The reference design doesn't need any extra work to decode, but your design likely will.
        *  Do any extra decoding here before returning the result to the host. */
        write_packet(DECODE_MSG, new_frame->data, frame_size);
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
    flash_init();

    // Read starting flash values into our flash status struct
    flash_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t), "");
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
            subscription[i].id = DEFAULT_CHANNEL_ID;
        }

        // Write the starting channel subscriptions into flash.
        memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT*sizeof(channel_status_t));

        flash_erase_page(FLASH_STATUS_ADDR);
        flash_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t), "");
    }

    // Initialize the uart peripheral to enable serial I/O
    ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        // if uart fails to initialize, do not continue to execute
        while (1);
    }
}

// /* Code between this #ifdef and the subsequent #endif will
// *  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
// *  the projectk.mk file. */
#ifdef CRYPTO_EXAMPLE
void crypto_example(void) {
    // Example of how to utilize included simple_crypto.h

    // This string is 16 bytes long including null terminator
    // This is the block size of included symmetric encryption
    char *data = "Crypto Example!";
    uint8_t ciphertext[BLOCK_SIZE];
    uint8_t key[KEY_SIZE];
    uint8_t hash_out[HASH_SIZE];
    uint8_t decrypted[BLOCK_SIZE];

    char output_buf[128] = {0};

    // Zero out the key
    bzero(key, BLOCK_SIZE);

    // Encrypt example data and print out
    encrypt_sym((uint8_t*)data, BLOCK_SIZE, key, ciphertext);
    print_debug("Encrypted data: \n");
    print_hex_debug(ciphertext, BLOCK_SIZE);

    // Hash example encryption results
    hash(ciphertext, BLOCK_SIZE, hash_out);

    // Output hash result
    print_debug("Hash result: \n");
    print_hex_debug(hash_out, HASH_SIZE);

    // Decrypt the encrypted message and print out
    decrypt_sym(ciphertext, BLOCK_SIZE, key, decrypted);
    sprintf(output_buf, "Decrypted message: %s\n", decrypted);
    print_debug(output_buf);
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
    // init_secret();

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

            // #ifdef CRYPTO_EXAMPLE
            //     // Run the crypto example
            //     // TODO: Remove this from your design
            //     crypto_example();
            // #endif // CRYPTO_EXAMPLE
            list_channels();
            break;

        // Handle decode command
        case DECODE_MSG:
            STATUS_LED_PURPLE();
            decode(pkt_len, (frame_packet_t *)uart_buf);
            break;

        // Handle subscribe command
        case SUBSCRIBE_MSG:
            STATUS_LED_YELLOW();
            update_subscription(pkt_len, (update_packet_t *)uart_buf);
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
