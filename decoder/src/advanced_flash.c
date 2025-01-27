#include "advanced_flash.h"
#include "flc.h"
#include "icc.h"
#include "nvic_table.h"
#include "types.h"
#include <stdio.h>




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

// Consider enabling these bits
// Have to enable these two to check the status
// MXC_F_FLC_INTR_AFIE
// If bit is 1, interrupt will occur on flash access failure
// MXC_F_FLC_INTR_DONEIE
// If bit is 1, interrupt will occur on flash complete

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
void flash_read(uint32_t address, void *buffer, uint32_t len, char *key) {
    MXC_FLC_Read(address, (uint32_t*)buffer, len);
    // Decrypt after read:
    // decrypt(buffer, key, len);
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
int flash_write(uint32_t address, void *buffer, uint32_t len, char *key) {
    // Encrypt before write
    // encrypt(buffer, key, len);

    // Check the bounds of the address to make sure write is to flash
    if (address < MXC_FLASH_MEM_BASE || address >= (MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE)) 
        return -1;
    
    int error = MXC_FLC_Write(address, len, buffer);
    return error;
}

// /**
//  * @brief Flash Read Secrets
//  * 
//  * @param channel_id: int, channel id of the secret to read
//  * @param buf: secret_t*, pointer to buffer for data to be read into
//  * @return int: return negative if failure, zero if success
//  */
// int read_secrets(int channel_id, secret_t* secret_buffer) {
//     uint32_t memory_addr=channel_id*sizeof(secret_t)+SECRET_BASE_ADDRESS;
//     flash_read(memory_addr,secret_t,sizeof(secret_t),); //k is not implemented
// }

// /**
//  * @brief Flash Write Secrets
//  * @param s: secret_t*, pointer to secret to write
//  */
// int write_secrets(secret_t* s) {
//     //First retrieve the channel ID to determine the offset
//     int channel_id=s->channel_id;
//     //then calculate the memory offset from this channel id
//     uint32_t memory_addr=channel_id*sizeof(secret_t)+SECRET_BASE_ADDRESS;

//     //now I need to write into this memory address // the key is not done yet
//     int error= flash_write(memory_addr,s,sizeof(secret_t),);

//     return error;
// }
