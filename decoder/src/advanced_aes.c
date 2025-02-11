#include "advanced_aes.h"

#include "aes.h"
#include "aes_revb.h"
#include "mxc_device.h"
#include "random.h"
#include "flc.h"
#include <string.h>

/**
 * @brief Set the AES key into thte AES key registers 
 */
void aes_set_key() {
	uint32_t key[4];
    MXC_FLC_Read(FLASH_KEY, key, 4 * sizeof(uint32_t)); // flash_read_raw
	MXC_AESKEYS->key0 = key[0];
	MXC_AESKEYS->key1 = key[1];
	MXC_AESKEYS->key2 = key[2];
	MXC_AESKEYS->key3 = key[3];
	memset(key, 0, 4 * sizeof(uint32_t));
}

int aes_init() {
// #ifndef MSDK_NO_GPIO_CLK_INIT
//     MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_AES);
//     MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_TRNG);
// #endif

	// Clear control
    MXC_AES->ctrl = 0x00;
	

	while (MXC_AES_IsBusy() != E_NO_ERROR) {}

    MXC_AES->ctrl |= ((uint32_t)(0x1UL << 0)); // enable control, position 0

    return E_NO_ERROR;
}
/**
 * @brief dummy encrypt with arbitrary data
 */
int dummy_encrypt() {
	mxc_aes_req_t req;
	uint32_t dummy_input[4];
	uint32_t dummy_output[4];

	req.length = 4;
	req.inputData = dummy_input;
	req.resultData = dummy_output;
	req.keySize = 0;
	req.encryption = MXC_AES_ENCRYPT_EXT_KEY;

	// MXC_AES_Init();
	aes_init();

	MXC_AES_Encrypt(&req);

	return E_NO_ERROR;
}
/** 
 * @brief Encrypt the data using AES
 * @param len Length of the data
 * @param data pointer to buffer containing data to be encrypted
 * @param enc_data pointer to buffer to store encrypted data
*/
int encrypt(uint32_t len, uint32_t* data, uint32_t* enc_data) {
	mxc_aes_req_t req;

	req.length = len;
	req.inputData = data;
	req.resultData = enc_data;
	req.keySize = 0;
	req.encryption = MXC_AES_ENCRYPT_EXT_KEY;

	// MXC_AES_Init();
	aes_init();

	MXC_AES_Encrypt(&req);

	return E_NO_ERROR;
}
/**
 * @brief Decrypt the data using AES
 * @param len Length of the data
 * @param enc_data pointer to buffer containing data to be decrypted
 * @param dec_data pointer to buffer to store decrypted data
 */
int decrypt(uint32_t len, uint32_t* enc_data, uint32_t* dec_data) {
	mxc_aes_req_t req;

	if ((MXC_AES->ctrl & MXC_F_AES_CTRL_EN) == 0) {
		dummy_encrypt();
	}

	req.length = len;
	req.inputData = enc_data;
	req.resultData = dec_data;
	req.keySize = 0;
	req.encryption = MXC_AES_DECRYPT_INT_KEY;

	MXC_AES_Decrypt(&req);

	MXC_AES_Shutdown();

	return E_NO_ERROR;
}
