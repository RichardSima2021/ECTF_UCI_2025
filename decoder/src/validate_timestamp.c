#include "decoder.h"
#include "advanced_flash.h"
#include <stdint.h>
#include <string.h>
# define TIMESTAMP_LENGTH 8;


int check_two_timestamp(timestamp_t plaintext_ts, timestamp_t extracted_timestamp){
    //do a memcmp and return 0 if the result is correct, else return 1
    // Convert the extracted timestamp to unit64_t
    uint64_t extracted_ts = 0;

    // Compare timestamps, return 0 if they match, 1 otherwise
    int result=memcmp(&plaintext_ts, &extracted_timestamp, TIMESTAMP_LENGTH);
    return result;
}


int check_increasing(int channel_id, timestamp_t extracted_timesamp){
    uint64_t extract_ts=0;
    uint64_t current_ts=0;
    memcpy(&extract_ts,extracted_timesamp,8);

    //1. extract the channel_status strcuture from the flash


    //2. check if the timestamp is strictly greater than that

}



int validate_timestamp(int channel_id, timestamp_t plaintext_ts, timestamp_t extracted_timestamp){
    //if check two are good, then another if check increasing, if both ok, return 0, else return 1
    if (check_two_timestamp(plaintext_ts, extracted_timestamp) == 0){
        if (check_increasing(channel_id, extracted_timestamp) == 0){
            return 0
        }
    }
    //else
    return 1;

}