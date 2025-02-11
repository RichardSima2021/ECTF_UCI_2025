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


#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>

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



// These are some temperory keys for developing purposes. Need to be deleted later
uint8_t mask_key[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
uint8_t message_key[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
uint8_t data_key[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};



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


int get_frame_size(uint8_t * frame){
    int size = 0;
    for(int i = 0; i<FRAME_SIZE; i++){
        if(!frame[i]){
            break;
        }
        size++;
    }
    return size;
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
int extract(interwoven_bytes *intrwvn_msg, subscription_update_packet_t *subscription_info, uint8_t *checksum) {
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

    // Alignment issue
    uint8_t temp_subscription_arr[20];

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
    // get iv from packet (last 16 bytes)

    char iv[16];
    memcpy(iv, &packet.encrypted_packet[52], 16);

    // encrypted_packet = channel_id (4 bytes) + ciphertext
    //      ciphertext  = 48 bytes interweaved

    // 1.
    memcpy(&channel_id, packet->encrypted_packet, sizeof(channel_id_t));
    // 1.5
    memcpy(&interwoven_encrypted, packet->encrypted_packet + sizeof(channel_id_t), sizeof(interwoven_encrypted));

    // 2.
    read_secrets(channel_id, channel_secrets);

    // 3.
    decrypt_sym(&interwoven_encrypted, 48, channel_secrets->subscription_key, iv, &interwoven_decrypted);

    // 4. & 5.
    subscription_update_packet_t *update;
    update->channel = channel_id;

    uint8_t checksum [20];

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
    flash_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
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
    char output_buf[BUF_LEN] = {0};
    uint16_t frame_size;

    channel_id_t channel;
    timestamp_t timestamp;
    timestamp_t timestamp_decrypted;
    uint8_t ts_prime[C1_LENGTH];
    uint8_t ts_decrypted[sizeof(timestamp_t)];
    uint8_t nonce[KEY_SIZE];
    uint8_t frame_data[FRAME_SIZE];
    uint8_t c1_key[KEY_SIZE] = {0};
    uint8_t c2_key[KEY_SIZE] = {0};


    // Get the plain text info from the encrypted frame
    channel = new_frame->channel;
    timestamp = new_frame->timestamp;

    // secret_t *channel_secrets;
    // read_secrets(channel, channel_secrets);

    // mask_key = channel_secrets->mask_key;
    // message_key = channel_secrets->msg_key;
    // data_key = channel_secrets->data_key;


    // Check that we are subscribed to the channel...
    print_debug("Checking subscription\n");
    if (!is_subscribed(channel)) {
        STATUS_LED_RED();
        sprintf(
            output_buf,
            "Receiving unsubscribed channel data.  %u\n", channel);
        print_error(output_buf);
        return -1;
    }

    print_debug("Subscription Valid\n");

    // Todo: Decrypt c1 and c2, and validate timestamps

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


    // Start to decrypt c2
    // Construct the key for c2
    // XOR data key with the nounce to get the decryption key for c2
    if (xorArrays(nonce, 16, data_key, KEY_SIZE, c2_key) != 0) {
        print_error("Failed to XOR nonce and data_key\n");
        return -1;
    }

    // Calculate the length of c2
    int c2_length = pkt_len - sizeof(channel_id_t) - sizeof(timestamp_t) - KEY_SIZE - C1_LENGTH;

    // Decrypt c2 with the decryption key and get the frame data
    memset(frame_data, 0, FRAME_SIZE);
    decrypt_sym(new_frame->c2, c2_length, c2_key, new_frame->iv, frame_data);


    // TODO: Validation of Time Stamp Here

    
    write_packet(DECODE_MSG, frame_data, get_frame_size(frame_data));
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

    // Read starting flash values into our flash status struct
    MXC_FLC_Read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
    //if (true) {
        /* If this is the first boot of this decoder, mark all channels as unsubscribed.
        *  This data will be persistent across reboots of the decoder. Whenever the decoder
        *  processes a subscription update, this data will be updated.
        */
        print_debug("First boot.  Setting flash...\n");

        // Generate random flash key
        generate_key(MXC_AES_128BITS, FLASH_KEY);
        aes_set_key();

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
        MXC_FLC_Write(FLASH_STATUS_ADDR, sizeof(flash_entry_t), &decoder_status);


        /** TODO: Call generate secrets to load tachi keys */
        
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

    uint8_t iv[BLOCK_SIZE] = {1};

    char output_buf[128] = {0};

    // // Zero out the key
    bzero(key, BLOCK_SIZE);

    // // Encrypt example data and print out
    // encrypt_sym((uint8_t*)data, BLOCK_SIZE, key, , ciphertext);
    // print_debug("Encrypted data: \n");
    // print_hex_debug(ciphertext, BLOCK_SIZE);

    // // Hash example encryption results
    // hash(ciphertext, BLOCK_SIZE, hash_out);

    // // Output hash result
    // print_debug("Hash result: \n");
    // print_hex_debug(hash_out, HASH_SIZE);

    // // Decrypt the encrypted message and print out
    decrypt_sym(ciphertext, BLOCK_SIZE, key, iv, decrypted);
    sprintf(output_buf, "Decrypted message: %s\n", decrypted);
    print_debug(output_buf);
}
#endif  //CRYPTO_EXAMPLE


void flash_test() {
    char output_buf[BUF_LEN] = {0};
    uint8_t data[16] = "Hello World!";
    uint8_t read_data[16] = {0};

    //flash_erase_page(FLASH_STATUS_ADDR);
    //flash_write(FLASH_STATUS_ADDR, data, sizeof(data));
    //flash_read(FLASH_STATUS_ADDR, read_data, sizeof(read_data));

    //sprintf(output_buf, "Flash test: %s\n", read_data);
    //print_debug(output_buf);

    char c;
    int status;
    while (1) {
        c = uart_readbyte(&status);
        if (c == 'w') {
            flash_erase_page(FLASH_KEY - MXC_FLASH_PAGE_SIZE);
            flash_write(FLASH_KEY - MXC_FLASH_PAGE_SIZE, data, sizeof(data));
            sprintf(output_buf, "Wrote to flash\n", data);
            print_debug(output_buf);
        } else if (c == 'r') {
            flash_read(FLASH_KEY - MXC_FLASH_PAGE_SIZE, read_data, sizeof(read_data));
            sprintf(output_buf, "Flash test: %s\n", read_data);
            print_debug(output_buf);
        }
        //uart_writebyte(c);
    }
}


void uart_test() {
    char c;
    int status;
    while (1) {
        c = uart_readbyte(&status);
        uart_writebyte(c);
    }
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
    // init_secret();

    print_debug("Decoder Booted!\n");

    // #ifdef CRYPTO_EXAMPLE

    // // print_debug("\n\nCrypto Example\n");

    // // uint8_t ciphertext[BLOCK_SIZE] = "Hello, World!";
    // // uint8_t key[KEY_SIZE];
    // // uint8_t decrypted[BLOCK_SIZE];
    // // decrypt_sym(ciphertext, BLOCK_SIZE, key, decrypted);
    // // print_debug(decrypted);

    // // print_debug("\n\n");

    // crypto_example();

    // #endif


    flash_test();
    //uart_test();



    
    uint8_t data[] = { 0x01, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x62, 0x7C, 0xE5, 0x27, 0xA1, 0xC8, 0xEA, 0x9B, 0x05, 0x82, 0x9A, 0x2F, 0x19, 0x11, 0x6B, 0xF6, 0x3B, 0x02, 0x05, 0xFF, 0x0E, 0xD9, 0xEE, 0xD3, 0xC5, 0xF6, 0xCC, 0xBC, 0xEA, 0x1E, 0x99, 0x3F, 0x81, 0xD4, 0x7B, 0xDA, 0x66, 0xD7, 0x02, 0x6D, 0xE7, 0x55, 0x36, 0x1C, 0x7C, 0xD3, 0xDE, 0x34 };

    decode(76, (encrypted_frame_packet_t *)data);

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

            #ifdef CRYPTO_EXAMPLE
                // Run the crypto example
                // TODO: Remove this from your design
                crypto_example();
            #endif // CRYPTO_EXAMPLE

            // Print the boot flag
            // TODO: Remove this from your design
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
