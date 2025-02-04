#include "aes.h"
#include "aes_revb.h"
#include "mxc_device.h"

void aes_set_key(uint32_t* key, uint8_t num_blocks);

int dummy_encrypt();

int encrypt(uint32_t len, uint32_t* data, uint32_t* enc_data);

int decrypt(uint32_t len, uint32_t* enc_data, uint32_t* dec_data);
