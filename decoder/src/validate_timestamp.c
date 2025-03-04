#include "types.h"
#include "advanced_flash.h"
//#include "decoder.c"
#include <stdint.h>
#include <string.h>
#include "host_messaging.h"
#include "mpu.h"

#define TIMESTAMP_LENGTH 8

extern flash_entry_t decoder_status;
extern timestamp_t current_timestamp;

void clean_up(){
    flash_privileged_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    memset(&decoder_status, 0, sizeof(flash_entry_t));
}

int check_two_timestamp(timestamp_t plaintext_ts, timestamp_t extracted_timestamp){

    char output_buf[BUF_LEN] = {0};

    sprintf(
        output_buf,
        "Plaintext_ts: %u; extracted_ts: %u", plaintext_ts, extracted_timestamp);
    print_debug(output_buf);

    //Encoded frame looks like this: Channelid || Timestamp || C1 || C2 

    // Compare timestamps, return 1 if they match, 0 if not
    return plaintext_ts == extracted_timestamp;
}

//helper function, extract the index corresponding to the channel id.
int extract_channel_idx(int channel_id) {
    flash_privileged_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == channel_id) {
            if (decoder_status.subscribed_channels[i].active) {
                return i;
            }
        }
    }
    return -1;
}


int check_increasing(int channel_id, timestamp_t extracted_timestamp) {
    print_debug("Checking increasing");
    //extarct the subscription information
    // request_privilege();
    // MXC_FLC_Read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    // drop_privilege();
    
    //2. check if the timestamp is strictly greater than that
    int idx;
    idx = extract_channel_idx(channel_id);
    if (idx == -1) {
        // inactive channel/didn't find
        print_error("Didn't find channel");
        return 0;
    }

    flash_privileged_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));

    char output_buf[BUF_LEN] = {0};

        sprintf(
            output_buf,
            "Extracted timestamp: %u; current timestamp: %u", extracted_timestamp, current_timestamp);
        print_debug(output_buf);

    if (decoder_status.subscribed_channels[idx].fresh) {
        // if this channel has not received anything yet, then current timestamp can = extracted timestamp
        if (extracted_timestamp >= current_timestamp) {
            return 1;
        }
    } else if (extracted_timestamp > current_timestamp) {
        return 1;
    }

    print_error("Timestamp not increasing");
    return 0;

}

int within_frame(int channel_id, timestamp_t extracted_timestamp){

    int idx = extract_channel_idx(channel_id);    
    if (idx == -1) {
        return 0;
    }

    flash_privileged_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));

    char output_buf[BUF_LEN] = {0};

    sprintf(
        output_buf,
        "Extracted timestamp: %u; Channel start: %u; Channel end: %u", extracted_timestamp, decoder_status.subscribed_channels[idx].start_timestamp, decoder_status.subscribed_channels[idx].end_timestamp);
    print_debug(output_buf);

    if ((extracted_timestamp >= decoder_status.subscribed_channels[idx].start_timestamp)) {
        if ((extracted_timestamp <= decoder_status.subscribed_channels[idx].end_timestamp)) {
            return 1;
        }
    } 
    
    return 0;
}

int update_current_timestamp(int channel_id, timestamp_t new_timestamp){
    //this function assumes that decoder_status has already been extracted from the flash
    int idx=extract_channel_idx(channel_id);
    if(idx == -1){
        return 0;
    }

    char output_buf[BUF_LEN] = {0};

    sprintf(
        output_buf,
        "Current timestamp: %u; New timestamp: %u", current_timestamp, new_timestamp);
    print_debug(output_buf);

    flash_privileged_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    current_timestamp = new_timestamp;
    decoder_status.subscribed_channels[idx].fresh = false;
    flash_erase_page(FLASH_STATUS_ADDR);
    flash_privileged_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));

    // request_privilege();
    // MXC_FLC_Write(FLASH_STATUS_ADDR, sizeof(flash_entry_t), &decoder_status);
    // drop_privilege();

    return 0;   // Idk if this is a flag used later
}

int validate_timestamp(int channel_id, timestamp_t plaintext_ts, timestamp_t extracted_timestamp){

    // returns 1 if timestamp is valid, 0 otherwise
    if (check_two_timestamp(plaintext_ts, extracted_timestamp)) {
        print_debug("Two timestamps match");

        if (check_increasing(channel_id, extracted_timestamp)) {
            print_debug("Strictly Increasing");

            if (within_frame(channel_id,extracted_timestamp)) {
                print_debug("Within timestamp interval");
                update_current_timestamp(channel_id, extracted_timestamp);
                return 1;
            }
        }
    }

    return 0;

}


