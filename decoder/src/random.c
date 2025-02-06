#include "random.h"

volatile int wait;
volatile int callback_result;

/**
 * @brief  Generate a random number
 * @return Random number
 */
int RandomInt(void){
    MXC_TRNG_Init();
    int ret = MXC_TRNG_RandomInt();
    MXC_TRNG_Shutdown();
    return ret;
}

/**
 * @brief  Generate a random number string with a given length into a buffer
 * @param  buf: buffer to store the random number string
 * @param  len: length of the random number string
 */
void Rand_String(uint8_t *buf, uint32_t len){
    MXC_TRNG_Init();
    MXC_TRNG_Random(buf, len);
    MXC_TRNG_Shutdown();
}

/**
 * @brief  Generate a random key with a given key size and set into aes key buffer
 * @param  keySize: key size according to AES key sizes 
 */
void generate_key(mxc_aes_keys_t keySize) {
    uint32_t keyLenChars;
    
    switch (keySize) {
    case MXC_AES_128BITS:
        keyLenChars = 4; // keybuffer len = 4 uint32
        break;
    case MXC_AES_192BITS:
        keyLenChars = 6; // keybuffer len = 6 uint32
        break;
    case MXC_AES_256BITS:
        keyLenChars = 8; // keybuffer len = 8 uint32
        break;
    };

    uint32_t keyBuffer[keyLenChars];
    Rand_String(keyBuffer, keyLenChars);
    aes_set_key(keyBuffer);
}


// void Rand_ASYC(uint8_t *data, uint32_t len){
//     MXC_TRNG_Init();
//     wait = 1;
//     NVIC_EnableIRQ(TRNG_IRQn);
//     MXC_TRNG_RandomAsync(data, len, &Test_Callback);
//     while (wait) {
//         continue;
//     }
//     MXC_TRNG_Shutdown();
// }


// void TRNG_IRQHandler(void)
// {
//     MXC_TRNG_Handler();
// }

// void Test_Callback(void *req, int result)
// {
//     wait = 0;
//     callback_result = result;
// }