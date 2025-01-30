#include "decoder.h"
#include "strings.h"


/** @brief Checks if the extracted timestamp is valid in terms of: 
 *              1. The given and the extracted match
 *              2. If SO: check if this is strcitly increasing from the current one
 *              3. If SO: check if this is within the frame
 *          NOTE: this does not update the current timestamp, even if the timestamp is valid
 *                Also this does not erase the sram for the decoder_status, as a global variable
 *                SWE should manually do the two things above for security purposes
 *
 *  @param channel_id The channel number to be checked.
 *  @param plaintext_ts the given timestamp
 *  @param extracted_timestamp the extracted timstamp
 *  @return 1 if valid, 0 if not
*/

int validate_timestamp(int channel_id, timestamp_t plaintext_ts, timestamp_t extracted_timestamp);



/** @brief Once the validation is done, update the channel's timestamp the current one
 *         Write back the decoder_status to the flash
 * 
 *  @param channel_id The channel number to be checked.
 *  @param new_timestamp the timestamp for an update
 *  @return 1 if valid, 0 if not
*/

int update_current_timestamp(int channel_id, timestamp_t new_timestamp);


/** @brief Helper function to clean up the global decoder_status from the SRAM
 * 
*/

int clean_up(){
    return memset(&decoder_status, 0, sizeof(flash_entry_t));
}