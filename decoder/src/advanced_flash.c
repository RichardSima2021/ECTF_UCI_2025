#include "advanced_flash.h"
#include "flc.h"
#include "icc.h"
#include "nvic_table.h"
#include "types.h"
#include <stdio.h>
#include <string.h>
#include "mpu.h"

#include "secret.h"

#define READ_SECRETS_IN_DECODE_ADDRESS (decode + 58) // placeholder, change byte val
#define READ_SECRETS_IN_UPDATE_SUBSCRIPTION_ADDRESS (update_subscription + 40) // placeholder, change byte val

extern flash_entry_t decoder_status;

int decode(pkt_len_t pkt_len, encrypted_frame_packet_t *new_frame);
int update_subscription(pkt_len_t pkt_len, encrypted_update_packet *packet);
int check_increasing(int channel_id, timestamp_t extracted_timestamp);

static channel_id_t channel_list[] = CHANNEL_LIST;


/**
 * @brief ISR for the Flash Controller
 * 
 * This ISR allows for access to the flash through simple_flash to operate
 */
void flash_irq(void) {
    uint32_t interrupt_status;
    interrupt_status = MXC_FLC0-> intr;
    
    // Check if interrupt flag is set, clear if set
    if (interrupt_status & MXC_F_FLC_INTR_DONE)
        MXC_FLC0->intr = ~MXC_F_FLC_INTR_DONE;

    if (interrupt_status & MXC_F_FLC_INTR_AF)//Check Flash Access Fail Interrupt Flag
        MXC_FLC0->intr = ~MXC_F_FLC_INTR_AF;
}


/**
 * @brief Initialize the Advanced Flash Interface
 * 
 * Initializes the ISR and enables the Flash Interrupt
 * and disables the ICC
 */
void flash_init(void) {
    // Register the flash_irq to vector table
    MXC_NVIC_SetVector(FLC0_IRQn, flash_irq);
    // NVIC_EnableIRQ(FLC0_IRQn);//remove
    
    //MXC_F_FLC_INTR_DONEIE: If bit is 1, interrupt will occur on flash complete
    // MXC_F_FLC_INTR_AFIE: If bit is 1, interrupt will occur on flash access failure
    MXC_FLC_EnableInt(MXC_F_FLC_INTR_DONEIE | MXC_F_FLC_INTR_AFIE);
    MXC_ICC_Disable(MXC_ICC0);//Disable Cache
}


/**
 * @brief Flash Erase Page
 * 
 * @param address: uint32_t, address of flash page to erase
 * 
 * @return int: return negative if failure, zero if success
 * 
 * This function erases a page of flash such that it can be updated.
 * Flash memory can only be erased in a large block size called a page.
 * Once erased, memory can only be written one way e.g. 1->0.
 * In order to be re-written the entire page must be erased.
*/
int flash_erase_page(uint32_t address){
    return MXC_FLC_PageErase(address);
}


/**
 * @brief Flash Advanced Read
 * 
 * @param address: uint32_t, address of flash page to read
 * @param buffer: void*, pointer to buffer for data to be read into
 * @param size: uint32_t, number of bytes to read from flash
 * @param key: char*, pointer to key to decrypt the buffer with
 * 
 * This function reads data from the specified flash page into the buffer 
 * with the specified amount of bytes and decrypt the buffer with a built-in key
*/
void flash_read(uint32_t address, void *buffer, uint32_t len) {
    uint32_t ciphertext[len];

    MXC_FLC_Read(address, ciphertext, len);
    
    // Decrypt after read:
    decrypt(len, ciphertext, buffer);

    memset(ciphertext, 0, sizeof(ciphertext));
}

/**
 * @brief Flash Advanced Write
 * @param address: uint32_t, address of flash page to write
 * @param buffer: void*, pointer to buffer to write data from
 * @param size: uint32_t, number of bytes to write from flash
 * @param key: char*, pointer to key to encrypt the buffer with
 * @return int: return negative if failure, zero if success
 * This function encrypts data with a built-in key and then writes it 
 * to the specified flash page from the buffer passed
 * with the specified amount of bytes. Flash memory can only be written in one
 * way e.g. 1->0. To rewrite previously written memory see the 
 * flash_simple_erase_page documentation. 
*/
int flash_write(uint32_t address, void* buffer, uint32_t len) {
    // Encrypt before write
    // Check the bounds of the address to make sure write is to flash
    if (address < MXC_FLASH_MEM_BASE || address >= (MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE)) 
        return -1;
    
    uint32_t ciphertext[len];

    encrypt(len, buffer, ciphertext);
    
    int error = MXC_FLC_Write(address, len, ciphertext);

    memset(buffer, 0, len);

    return error;
}

__attribute__((noinline))
volatile uint32_t compute_memory_addr(int channel_id) {
    for (volatile int i = 0; i < CHANNEL_LIST_SIZE; i++) {
        if (channel_list[i] == channel_id) {
            uint32_t magic = i;
            uint32_t memory_addr=magic*sizeof(secret_t)+SECRET_BASE_ADDRESS;
            return memory_addr;
        }
    }
    return 0;
}

/**
 * @brief Flash Read Secrets
 * 
 * @param channel_id: int, channel id of the secret to read
 * @param buf: secret_t*, pointer to buffer for data to be read into
 * @return int: return negative if failure, zero if success
 */
__attribute__((noinline))
int read_secrets(int channel_id, secret_t* secret_buffer) {
    int error = 1;

#ifdef CONDITIONAL_PRIV_ESCALATION_ENABLED
    void* return_addr = __builtin_return_address(0);

    if((return_addr != READ_SECRETS_IN_DECODE_ADDRESS) &&
       (return_addr != READ_SECRETS_IN_UPDATE_SUBSCRIPTION_ADDRESS)) {
        while (1);
    }
#endif

    //Find the magic value for the corresponding channel ID
    volatile uint32_t memory_addr = compute_memory_addr(channel_id);
    if (memory_addr != 0)
        flash_privileged_read(memory_addr, secret_buffer, sizeof(secret_t));
    else {
        print_error("Didn't find channel during read_secrets");
        return error;
    }

    return 0;
}

/**
 * @brief Flash Write Secrets
 * @param s: secret_t*, pointer to secret to write
 */
int write_secrets(secret_t* s) {
    //First retrieve the channel ID to determine the offset
    channel_id_t channel_id=s->channel_id;
    int error;

    bool updated = false;

    //Find the magic value for the corresponding channel ID
    for (int i = 0; i < CHANNEL_LIST_SIZE; i++) {
        if (channel_id == channel_list[i]) {
            uint32_t magic = i;
            //then calculate the memory offset from this channel magic
            uint32_t memory_addr=magic*sizeof(secret_t)+SECRET_BASE_ADDRESS;
            error = flash_write(memory_addr, s, sizeof(secret_t));
            updated = true;
            break;
        }
    }

    if(!updated){
        print_error("Didn't find channel during write secrets");
    }

    return error;
}
