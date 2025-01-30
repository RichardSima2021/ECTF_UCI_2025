/******************************************************************************
 *
 * Copyright (C) 2022-2023 Maxim Integrated Products, Inc. All Rights Reserved.
 * (now owned by Analog Devices, Inc.),
 * Copyright (C) 2023 Analog Devices, Inc. All Rights Reserved. This software
 * is proprietary to Analog Devices, Inc. and its licensors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************************/

/**
 * @file        main.c
 * @brief       AES Example
 * @details     Encryption and decryption of AES on different modes (ECB and OFB) with different bit sizes (128, 192, and 256)
 */

/***** Includes *****/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mxc_device.h"
#include "board.h"
#include "dma.h"
#include "aes.h"
#include "trng.h"
/***** Definitions *****/
#define MXC_AES_DATA_LENGTH 4 //4 words

#define MXC_AES_ENC_DATA_LENGTH 4 //Always multiple of 4
//(equal to or greater than MXC_AES_DATA_LENGTH)

int RandomInt(void){
    MXC_TRNG_Init();
    int ret = MXC_TRNG_RandomInt();
    MXC_TRNG_Shutdown();
    return ret;
}

void Rand_String(uint8_t *buf, uint32_t len){
    MXC_TRNG_Init();
    MXC_TRNG_Random(buf, len);
    MXC_TRNG_Shutdown();
}


void generate_key(uint32_t* keyBuffer, mxc_aes_keys_t keySize) {
    uint32_t keyLenChars;
    
    switch (keySize) {
    case MXC_AES_128BITS:
        keyLenChars = 16; // keybuffer len = 4 uint32
        break;
    case MXC_AES_192BITS:
        keyLenChars = 24; // keybuffer len = 6 uint32
        break;
    case MXC_AES_256BITS:
        keyLenChars = 32; // keybuffer len = 8 uint32
        break;
    };
    Rand_String(keyBuffer, keyLenChars);
}

void fill_request(mxc_aes_req_t* request, uint32_t bufferLength, uint32_t* inputDataBuffer, uint32_t* resultDataBuffer, mxc_aes_keys_t keySize) {
    request->length = bufferLength;
    request->inputData = inputDataBuffer;
    request->resultData = resultDataBuffer;
    request->keySize = keySize;
}

int AES_encrypt(mxc_aes_req_t* request)
{
    int result = E_NO_ERROR;

    request->encryption = MXC_AES_DECRYPT_EXT_KEY;

    result += MXC_AES_Init();
    result += MXC_AES_Encrypt(request);

    return result;
}

int AES_decrypt(mxc_aes_req_t* request)
{
    int result = E_NO_ERROR;
    
    request->encryption = MXC_AES_DECRYPT_INT_KEY; 
    result += MXC_AES_Decrypt(request);
    result += MXC_AES_Shutdown();

    return result;
}

// int main(void)
// {
//     printf("\n***** AES Example *****\n");

//     int fail = 0;
//     MXC_DMA_ReleaseChannel(0);
//     NVIC_EnableIRQ(DMA0_IRQn);

//     // uint32_t inputData[MXC_AES_DATA_LENGTH] = { 0x873AC125, 0x2F45A7C8, 0x3EB7190,  0x486FA931};
//     uint32_t encryptedData[MXC_AES_ENC_DATA_LENGTH] = { 0 };
//     uint32_t decryptedData[MXC_AES_DATA_LENGTH] = { 0 };

//     char * inputData = "aaaaaaaaaaaaaaa";
//     uint32_t buffer[4];
//     // generate_key(buffer, MXC_AES_128BITS);
    
//     // MXC_AES_SetExtKey(buffer, MXC_AES_128BITS);


//     volatile mxc_aes_req_t req;

//     fill_request(&req, MXC_AES_DATA_LENGTH, inputData, encryptedData, MXC_AES_128BITS);
    
//     //ECB
//     printf("\nAES 128 bits Key Test\n");
//     fail += AES_encrypt(&req);
    
//     fill_request(&req, MXC_AES_DATA_LENGTH, encryptedData, decryptedData, MXC_AES_128BITS);

//     fail += AES_decrypt(&req);

//     if (fail != 0) {
//         printf("\nExample Failed\n");
//         return E_FAIL;
//     }
    
//     if (memcmp(inputData, decryptedData, MXC_AES_DATA_LENGTH) != 0) {
//         printf("\nData Mismatch");
//         return 1;
//     }
    

//     printf("\nExample Succeeded\n");
//     return E_NO_ERROR;
// }