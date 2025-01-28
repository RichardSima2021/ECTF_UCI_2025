#include "decoder.h"
#include "advanced_flash.h"
#include <stdint.h>
#include <string.h>
# define TIMESTAMP_LENGTH 8;


int check_two_timestamp(char* plaintext_ts, char* extracted_timesamp){
    //do a memcmp and return 0 if the result is correct, else return 1

}

int check_increasing(int channel_id, char* extracted_timesamp){
    uint64_t extract_ts=0;
    memcpy(&extract_ts,extracted_timesamp,8);

    //1. extract the channel_status strcuture from the flash


    //2. check if the timestamp is strictly greater than that
}



int validate_timestamp(int channel_id, uint64_t plaintext_ts, char* extracted_timesamp){
    //Do a nested if

    //if check two are good, then another if check increasing, if both ok, return 0, else return 1
    //stub
    return 0;

}