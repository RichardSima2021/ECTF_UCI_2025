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
#include "advanced_flash.h"
#include "mxc_delay.h"
#include "advanced_flash.h"
#include "host_messaging.h"
#include "types.h"
#include "random.h"
#include "advanced_uart.h"
#include "mpu.h"

#include "secret.h"
#include "validate_timestamp.h"


#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>


/* Code between this #ifdef and the subsequent #endif will
*  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
*  the projectk.mk file. */
#ifdef CRYPTO_EXAMPLE
// /* The simple crypto example included with the reference design is intended
// *  to be an example of how you *may* use cryptography in your design. You
// *  are not limited nor required to use this interface in your design. It is
// *  recommended for newer teams to start by only using the simple crypto
// *  library until they have a working design. */
#include "simple_crypto.h"
#endif  //CRYPTO_EXAMPLE

#ifndef DECODER_ID
#define DECODER_ID 0xDEADBEEF
#endif


/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

// This is used to track decoder subscriptions
flash_entry_t decoder_status;

timestamp_t current_timestamp;
bool global_freshness;


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
    flash_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    // Check if the decoder has has a subscription
    for (int i = 1; i <= MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == channel && decoder_status.subscribed_channels[i].active) {
            return 1;
        }
    }
    return 0;
}



int xorArrays(uint8_t *arr1, size_t arr1_len, uint8_t *arr2, size_t arr2_len, u_int8_t* result) {

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
    flash_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));

    for (uint32_t i = 1; i <= MAX_CHANNEL_COUNT; i++) {
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

/**
 * @brief Validates the checksum of the subscription information
 * 
 * @param chksm The checksum to be validated
 * 
 * @return 0 upon success. -1 if error
 */
int validate(uint8_t *chksm, uint8_t *check_sum) {
    // Validate checksum with comparator value
    if (memcmp(chksm, check_sum, 20) != 0) {
        return -1;
    }
    return 0;
}

/** @brief Extracts subscription information and checksum from interwoven message.
 * 
 *  @param intrwvn_msg A pointer to the beginning of our interwoven subscription information
 *  @param subscription_info A pointer to the output of the extracted subscription information
 *  @param chksm A pointer to the output of the extracted checksum
 * 
 *  @return 0 upon success. -1 if error
 */
int extract(uint8_t *intrwvn_msg, subscription_update_packet_t *subscription_info, uint8_t *chksm) {
    if (intrwvn_msg == NULL) return -1;
    if (subscription_info == NULL) return -1;
    if (chksm == NULL) return -1;


    // Alignment issue
    uint8_t temp_subscription_arr[21]; // 20 char + null terminator

    // Extract the interwoven message into their respective character arrays
    for (int i = 0; i < 40; i++) {
        if (i % 2 == 0) {
            temp_subscription_arr[i / 2] = intrwvn_msg[i];
        }
        else {
            chksm[i / 2] = intrwvn_msg[i];
        }
    }

    // Null-terminate the output strings
    temp_subscription_arr[20] = '\0';
    chksm[20] = '\0';


    // Pull individual values from temp_subscription_arr
    subscription_info->decoder_id = (temp_subscription_arr[3] << 24) + (temp_subscription_arr[2] << 16) + (temp_subscription_arr[1] << 8) + (temp_subscription_arr[0]);
    subscription_info->start_timestamp = ((timestamp_t)temp_subscription_arr[4]) + ((timestamp_t)temp_subscription_arr[5] << 8) + ((timestamp_t)temp_subscription_arr[6] << 16) + ((timestamp_t)temp_subscription_arr[7] << 24) + ((timestamp_t)temp_subscription_arr[8] << 32) + ((timestamp_t)temp_subscription_arr[9] << 40) + ((timestamp_t)temp_subscription_arr[10] << 48) + ((timestamp_t)temp_subscription_arr[11] << 56);
    subscription_info->end_timestamp = ((timestamp_t)temp_subscription_arr[12]) + ((timestamp_t)temp_subscription_arr[13] << 8) + ((timestamp_t)temp_subscription_arr[14] << 16) + ((timestamp_t)temp_subscription_arr[15] << 24) + ((timestamp_t)temp_subscription_arr[16] << 32) + ((timestamp_t)temp_subscription_arr[17] << 40) + ((timestamp_t)temp_subscription_arr[18] << 48) + ((timestamp_t)temp_subscription_arr[19] << 56);
    
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
int found_duplicate_channel_id() {
    flash_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    int i;
    int j;
    for (i = 0; i <= MAX_CHANNEL_COUNT; i++) {
        for (j = 0; j <= MAX_CHANNEL_COUNT; j++) {
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

    secret_t channel_secrets;
    uint8_t interwoven_decrypted[48];
    memset(interwoven_decrypted, 0, 48);
    subscription_update_packet_t update;

    update.channel = 0;
    update.decoder_id = 0;
    update.end_timestamp = 0;
    update.start_timestamp = 0;

    if(read_secrets(packet->channel, &channel_secrets)){
        return -1;
    }

    decrypt_sym(packet->interwoven_bytes, 48, &channel_secrets.subscription_key, packet->iv, interwoven_decrypted);


    update.channel = packet->channel;

    if (update.channel == EMERGENCY_CHANNEL) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
        return -1;
    }

    uint8_t chksm [21]; // 20 chars + null term
    memset(chksm, 0, 20);

    if (extract(interwoven_decrypted, &update, chksm) != 0) {
        STATUS_LED_RED();
        print_error("Failed to extract\n");
        return -1;
    }

    // Check decoder id match
    if (update.decoder_id != DECODER_ID){
        STATUS_LED_RED();
        print_error("The decoder id doesn't match\n");
        return -1;
    }
    
    // Validate the checksum
    if (validate(chksm, &channel_secrets.check_sum) == -1) {
         STATUS_LED_RED();
         print_error("Failed to validate checksum");
         return -1;
    }

    // If we find duplicate channel ids (this should not happen) Check before modifying
    if (found_duplicate_channel_id() == -1) {
        STATUS_LED_RED();
        print_error("Channel list should not contain duplicates\n");
        return -1;
    }

    if (update.start_timestamp >= update.end_timestamp){
        STATUS_LED_RED();
        print_error("start_timestamp >= end_timestamp");
        return -1;
    }

    flash_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));

    bool modified = false;
    int active_channel = 0;
    // Find the first empty slot in the subscription array
    for (int i = 1; i <= MAX_CHANNEL_COUNT; i++) {
        
        // if this channel is the same ID as incoming channel info or it's not an active channel
        if (decoder_status.subscribed_channels[i].id == update.channel || !decoder_status.subscribed_channels[i].active) {
            // already performed modification && found duplicate channel id
            if (modified && decoder_status.subscribed_channels[i].id == update.channel) {
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
                decoder_status.subscribed_channels[i].id = update.channel;
                // set start timestamp
                decoder_status.subscribed_channels[i].start_timestamp = update.start_timestamp;
                // set end timestamp
                decoder_status.subscribed_channels[i].end_timestamp = update.end_timestamp;
                // set fresh flag
                modified = true;
                active_channel++;
            }
            
        }
        else if(decoder_status.subscribed_channels[i].active){
            active_channel++;
        }
    }

    // If we do not have any room for more subscriptions
    // And there was no modification because all channels were active
    if (active_channel >= MAX_CHANNEL_COUNT && !modified) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - max subscriptions installed\n");
        return -1;
    }

    flash_erase_page(FLASH_STATUS_ADDR);
    flash_privileged_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));

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
    //volatile char pad[500] = {0};
    char output_buf[BUF_LEN] = {0};
    uint16_t frame_size;

    timestamp_t timestamp;
    timestamp_t timestamp_decrypted;
    uint8_t ts_prime[C1_LENGTH];
    uint8_t ts_decrypted[sizeof(timestamp_t)];
    uint8_t nonce[KEY_SIZE];
    uint8_t frame_data[FRAME_SIZE];
    uint8_t c1_key[KEY_SIZE] = {0};
    uint8_t c2_key[KEY_SIZE] = {0};


    // Get the plain text info from the encrypted frame
    timestamp = new_frame->timestamp;

    secret_t channel_secrets;
    if(read_secrets(new_frame->channel, &channel_secrets)){
        return -1;
    }

    // Probably should not use memcpy here
    // alternative is:
    // uint8_t* mask_key = channel_secrets->mask_key;
    uint8_t mask_key[16];
    memcpy(mask_key, channel_secrets.mask_key, 16);
    uint8_t message_key[16];
    memcpy(message_key, channel_secrets.msg_key, 16);
    uint8_t data_key[16];
    memcpy(data_key, channel_secrets.data_key, 16);

    channel_id_t channel_id = new_frame->channel;

    // Check that we are subscribed to the channel...
    print_debug("Checking subscription\n");
    if (is_subscribed(channel_id) == 0) {
        STATUS_LED_RED();
        sprintf(
            output_buf,
            "Receiving unsubscribed channel data.  %u\n", channel_id);
        print_error(output_buf);
        // print_error("Unsubscribed channel");
        return -1;
    }    

    print_debug("Subscription Valid\n");

    // Decrypt c1 first
    
    // Construct the key for c1
    // XOR mask key with the timestamp
    memcpy(c1_key, &timestamp, sizeof(timestamp));
    if (xorArrays(c1_key, KEY_SIZE, mask_key, KEY_SIZE, c1_key) != 0) {
        print_error("Failed to XOR c1_key and mask_key\n");
        return -1;
    }
    // Hash the the XOR result from the previous step
    compute_hash(c1_key, KEY_SIZE, c1_key);

    // XOR the hash result with message key to get the decryption key for c1
    if (xorArrays(c1_key, KEY_SIZE, message_key, KEY_SIZE, c1_key) != 0) {
        print_error("Failed to XOR c1_key and message_key\n");
        return -1;
    }

    // Decrypt c1 with the decryption key and get timestamp prime
    decrypt_sym(new_frame->c1, C1_LENGTH, c1_key, new_frame->iv, ts_prime);


    // Extract nonce from timestamp prime
    memcpy(nonce, ts_prime, 8);
    memcpy(nonce + 8, ts_prime + 16, 8);

    
    memcpy(ts_decrypted, ts_prime + 8, sizeof(timestamp_t));
    timestamp_decrypted = *(timestamp_t*) ts_decrypted;

    // Validation of Time Stamp Here
    if (!validate_timestamp(channel_id, timestamp, timestamp_decrypted)) {
        STATUS_LED_RED();
        sprintf(
            output_buf,
            "Invalid timestamp  %llu\n", timestamp_decrypted);
        print_error(output_buf);
        return -1;
    }


    if (xorArrays(nonce, 16, data_key, KEY_SIZE, c2_key) != 0) {
        print_error("Failed to XOR nonce and data_key\n");
        return -1;
    }

    // Calculate the length of c2
    int c2_length = pkt_len - sizeof(channel_id_t) - sizeof(timestamp_t) - sizeof(frame_length_t) - KEY_SIZE - C1_LENGTH;

    // Decrypt c2 with the decryption key and get the frame data
    memset(frame_data, 0, FRAME_SIZE);
    decrypt_sym(new_frame->c2, c2_length, c2_key, new_frame->iv, frame_data);


    write_packet(DECODE_MSG, frame_data, new_frame->frame_length);

    return 0;
}

/** @brief Initializes peripherals for system boot.
*/
void init() {
    int ret;
    NVIC_DisableIRQ(DMA0_IRQn);//disable DMA interrupt
    NVIC_DisableIRQ(DMA1_IRQn);//disable DMA interrupt
    NVIC_DisableIRQ(DMA2_IRQn);//disable DMA interrupt
    NVIC_DisableIRQ(DMA3_IRQn);//disable DMA interrupt

    // Initialize the flash peripheral to enable access to persistent memory
    flash_init();

    uint32_t boot_flag;

    current_timestamp = 0;
    global_freshness = true;

    // Read starting flash values into our flash status struct
    MXC_FLC_Read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    MXC_FLC_Read(BOOT_FLAG_ADDR, &boot_flag, sizeof(uint32_t));
    if (boot_flag != FLASH_FIRST_BOOT) {//this is first boot
        /* If this is the first boot of this decoder, mark all channels as unsubscribed.
        *  This data will be persistent across reboots of the decoder. Whenever the decoder
        *  processes a subscription update, this data will be updated.
        */
        print_debug("First boot.  Setting flash...\n");

        // Generate random flash key
        generate_key(MXC_AES_128BITS, FLASH_KEY);
        aes_set_key();

        boot_flag = FLASH_FIRST_BOOT;

        channel_status_t subscription[MAX_CHANNEL_COUNT + 1];

        for (int i = 1; i <= MAX_CHANNEL_COUNT; i++){
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;
            subscription[i].id = DEFAULT_CHANNEL_ID;
        }

        subscription[0].start_timestamp = 0;
        subscription[0].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
        subscription[0].active = true;
        subscription[0].id = 0;
        

        // Write the starting channel subscriptions into flash.
        memcpy(decoder_status.subscribed_channels, subscription, (MAX_CHANNEL_COUNT+1)*sizeof(channel_status_t));

        flash_erase_page(FLASH_STATUS_ADDR);
        flash_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));

        flash_erase_page(BOOT_FLAG_ADDR);
        MXC_FLC_Write(BOOT_FLAG_ADDR, sizeof(uint32_t), &boot_flag);


        /** TODO: Call generate secrets to load tachi keys */

        init_secret();
        
    } else {// If not first boot
        aes_set_key();
    }
    

    
    // Initialize the uart peripheral to enable serial I/O
    ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        // if uart fails to initialize, do not continue to execute
        while (1);
    }


    // Last thing we do is set up MPU to set up read/write accesses
    mpu_setup();
    __enable_irq();
    drop_privilege();
}


/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void) {

    char output_buf[BUF_LEN] = {0};
    uint8_t uart_buf[BUF_LEN]; // longest possible packet is 124 bytes

    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // initialize the device
    init();

    print_debug("Decoder Booted!\n");



    // process commands forever
    while (1) {
        print_debug("Ready\n");

        STATUS_LED_GREEN();

        result = read_packet(&cmd, uart_buf, &pkt_len);

        if (result < 0) {
            STATUS_LED_ERROR();
            print_error("Failed to receive cmd from host. Flushing UART...\n");
            uart_flush(); // Flush UART after recieving a bad packet
            continue;
        }

        // Handle the requested command
        switch (cmd) {

        // Handle list command
        case LIST_MSG:
            STATUS_LED_CYAN();
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
            update_subscription(pkt_len, (encrypted_update_packet *)uart_buf);
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
