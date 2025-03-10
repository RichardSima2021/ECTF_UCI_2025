#ifndef __TYPES__
#define __TYPES__

#include <stdint.h>
#include <stdbool.h>

#include "mxc_device.h"
#include "board.h"

/**********************************************************
 ******************* PRIMITIVE TYPES **********************
 **********************************************************/

#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t
#define frame_length_t uint32_t

/**********************************************************
 *********************** CONSTANTS ************************
 **********************************************************/

#define BUF_LEN 512
#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 64
#define DEFAULT_CHANNEL_ID 0
#define DEFAULT_MAGIC -1
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
// This is a canary value so we can confirm whether this decoder has booted before
#define FLASH_FIRST_BOOT 0xDEADBEEF
#define KEY_SIZE 16
#define C1_LENGTH 32







/**********************************************************
 ********************* STATE MACROS ***********************
 **********************************************************/

// Calculate the flash address where we will store channel info as the 2nd to last page available
#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))

//TAICHI Key
#define SECRET_BASE_ADDRESS ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (3 * MXC_FLASH_PAGE_SIZE))

//The flash read write key
#define FLASH_KEY ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (4 * MXC_FLASH_PAGE_SIZE)) // we put it on 4th page, in what is no access region

// Address of first boot flag
#define BOOT_FLAG_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (5 * MXC_FLASH_PAGE_SIZE))

/**********************************************************
 *********** COMMUNICATION PACKET DEFINITIONS *************
 **********************v ************************************/

#pragma pack(push, 1) // Tells the compiler not to pad the struct members
// for more information on what struct padding does, see:
// https://www.gnu.org/software/c-intro-and-ref/manual/html_node/Structure-Layout.html

typedef struct{
    channel_id_t channel;
    timestamp_t timestamp;
    frame_length_t frame_length;
    uint8_t iv[KEY_SIZE];
    uint8_t c1[C1_LENGTH];
    uint8_t c2[FRAME_SIZE];
} encrypted_frame_packet_t;

typedef struct {
    channel_id_t channel;
    uint8_t interwoven_bytes[48];
    uint8_t iv[KEY_SIZE];
}   encrypted_update_packet;

typedef uint8_t interwoven_bytes[48];

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

typedef struct {
    uint32_t channel_id;
    char mask_key[16];
    char msg_key[16];
    char data_key[16];
    char subscription_key[16];
    char check_sum[20];
    char padding[8];
} secret_t;


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
    // uint32_t first_boot; // if set to FLASH_FIRST_BOOT, device has booted before.
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT + 1];
} flash_entry_t;

typedef uint8_t interwoven_bytes[48];

#endif
