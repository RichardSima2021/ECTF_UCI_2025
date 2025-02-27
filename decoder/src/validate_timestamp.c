#include "types.h"
#include "advanced_flash.h"
//#include "decoder.c"
#include <stdint.h>
#include <string.h>
#define TIMESTAMP_LENGTH 8

extern flash_entry_t decoder_status;

void clean_up(){
    memset(&decoder_status, 0, sizeof(flash_entry_t));
}

int check_two_timestamp(timestamp_t plaintext_ts, timestamp_t extracted_timestamp){
    //do a memcmp and return 0 if the result is correct, else return 1
    // Convert the extracted timestamp to unit64_t

    //Encoded frame looks like this: Channelid || Timestamp || C1 || C2 

    uint64_t extracted_ts = 0;

    // Compare timestamps, return 0 if they match, 1 otherwise
    int result=memcmp(&plaintext_ts, &extracted_timestamp, TIMESTAMP_LENGTH);
    return result+1;
}

//helper function, extract the index corresponding to the channel id.
int extract_channel_idx(int channel_id){
    for(int i=0;i<MAX_CHANNEL_COUNT; i++){
        if(!decoder_status.subscribed_channels[i].active){
            if (decoder_status.subscribed_channels[i].id== channel_id){
                return i;
            }
        }
    }
    return -1;
}


int check_increasing(int channel_id, timestamp_t extracted_timestamp){

    //extarct the subscription information
    flash_privileged_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));

    //2. check if the timestamp is strictly greater than that
    int idx=extract_channel_idx(channel_id);
    if(idx==-1){
        return 0;
    }

    if(extracted_timestamp > decoder_status.subscribed_channels[idx].current_timestamp){
        return 1;
    }
    return 0;

}

int within_frame(int channel_id, timestamp_t extracted_timestamp){

    int idx=extract_channel_idx(channel_id);
    if(idx==-1){
        return 0;
    }
    
    if((extracted_timestamp > decoder_status.subscribed_channels[idx].start_timestamp)){
        if((extracted_timestamp < decoder_status.subscribed_channels[idx].end_timestamp)){
            return 1;
        }
    }
    return 0;
}



int validate_timestamp(int channel_id, timestamp_t plaintext_ts, timestamp_t extracted_timestamp){
    //if check two are good, then another if check increasing, if both ok, return 0, else return 1
    if (check_two_timestamp(plaintext_ts, extracted_timestamp) == 0){
        if (check_increasing(channel_id, extracted_timestamp) == 0){
            if(within_frame(channel_id,extracted_timestamp)==0){
                return 1;
            }
        }
    }
    //else
    return 0;

}


int update_current_timestamp(int channel_id, timestamp_t new_timestamp){
    //this function assumes that decoder_status has already been extracted from the flash
    int idx=extract_channel_idx(channel_id);
    if(idx==-1){
        return 0;
    }
    
    decoder_status.subscribed_channels[idx].current_timestamp=new_timestamp;
    flash_privileged_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    return 0;   // Idk if this is a flag used later
}