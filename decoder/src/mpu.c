#include "mpu.h"
#include <stdint.h>
#include <stdio.h>


int update_subscription(pkt_len_t pkt_len, encrypted_update_packet *packet);
int update_current_timestamp(int channel_id, timestamp_t new_timestamp);
void read_secrets(int channel_id, secret_t* secret_buffer);

#define REQUEST_PRIVILEGE_IN_PRIVILEGED_READ_OFFSET (flash_privileged_read + 0x26) // placeholder
#define REQUEST_PRIVILEGE_IN_PRIVILEGED_WRITE_OFFSET (flash_privileged_write + 0x32) // placeholder

#define PRIVILEGED_READ_IN_READ_SECRETS_ADDRESS (read_secrets + 0x32) // TODO, placeholder currently
#define PRIVILEGED_WRITE_IN_UPDATE_SUBSCRIPTION_ADDRESS (update_subscription + 0x16A) // TODO, placeholder
#define PRIVILEGED_WRITE_IN_UPDATE_CURRENT_TIMESTAMP_ADDRESS (update_current_timestamp + 0x26) // TODO, placeholder

/**
 * @brief SVC Handler
 * @details This function is called when an SVC interrupt is triggered. It clears the control bit for privileged mode.
 */
void SVC_Handler(void) {
    __set_CONTROL(__get_CONTROL() & ~0x1);
    __ISB();
} 
/**
 * @brief request privilege
 * @details This function checks if the return address is the flash_privileged_read function 
 *          if it is, it requests privilege by calling the SVC interrupt. It will crash if its not the correct return address.
 */
void request_privilege() {
    void* return_addr = __builtin_return_address(0);

    if(return_addr == REQUEST_PRIVILEGE_IN_PRIVILEGED_READ_OFFSET ||
       return_addr == REQUEST_PRIVILEGE_IN_PRIVILEGED_WRITE_OFFSET){
            __asm("svc #0");
       }
}


/**
 * @brief Disable Privilege mode
 * @details This function disables the privilege mode by setting the CONTROL bit.
 *          It should be called immediately after the operation that requires privilege.
*/
void drop_privilege() {
    __set_CONTROL(__get_CONTROL() | 0x1);
    __ISB();
}


/**
* @brief    Setup the MPU
* @details  This function sets up the MPU to protect the ROM and Flash memory regions
*           from being written to.
* @returns  0 if successful
*/
uint8_t mpu_setup() {
    uint8_t i;

    // Ensure MPU is disabled
    MPU->CTRL = 0;

    // Check if MPU present, return error if not
    if (MPU->TYPE != 0) {
        return 1;
    }

    int disabled_regions[] = {1, 2, 3, 4, 5};
    int arr_size = 5;
    // Background Region
    MPU->RNR = 0;
    MPU->RBAR = MXC_ROM_MEM_BASE;
    MPU->RASR = (MPU_DEFS_RASR_SIZE_4GB | MPU_DEFS_NORMAL_MEMORY_WT | MPU_DEFS_RASE_AP_FULL_ACCESS | MPU_RASR_ENABLE_Msk);
    //MPU->RASR = (MPU_DEFS_RASR_SIZE_4GB | MPU_DEFS_NORMAL_MEMORY_WT | MPU_DEFS_RASE_AP_NO_ACCESS | MPU_RASR_ENABLE_Msk);

    // Secrets Region
    MPU->RNR = 7;
    MPU->RBAR = MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE - 3 * MXC_FLASH_PAGE_SIZE; 
    //MPU->RASR = (MPU_DEFS_RASR_SIZE_8KB | MPU_DEFS_NORMAL_MEMORY_WT | MPU_DEFS_RASE_AP_PRIV_RO | MPU_RASR_ENABLE_Msk);
    MPU->RASR = (MPU_DEFS_RASR_SIZE_8KB | MPU_DEFS_NORMAL_MEMORY_WT | MPU_DEFS_RASE_AP_RO | MPU_RASR_ENABLE_Msk);

    // Secrets Overlay Region
    MPU->RNR = 6;
    MPU->RBAR = MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE - 4 * MXC_FLASH_PAGE_SIZE;
    MPU->RASR = (MPU_DEFS_RASR_SIZE_32KB | MPU_DEFS_NORMAL_MEMORY_WT | MPU_DEFS_RASE_AP_NO_ACCESS | MPU_RASR_ENABLE_Msk);

    // Disable unused regions
    for (i = 0; i < arr_size; ++i) {
        MPU->RNR = disabled_regions[i];
        MPU->RBAR = 0;
        MPU->RASR = 0;
    }

    // Enable MPU
    //Random Delay
    Random_Delay();
    MPU->CTRL = MPU_CTRL_ENABLE_Msk;

    __DSB();
    __ISB();

    return 0;
}
/**
 * @brief read from flash in privileged mode
 * @details if the return address is correct, switch to privileged mode, if not crash, if privilege mode is enabled,
 *          read from flash, and then drop privilege
 */
void flash_privileged_read(uint32_t address, void *buffer, uint32_t len) {
    void* return_addr = __builtin_return_address(0);
    
    // TODO: Find correct offset after merge
    if(return_addr == PRIVILEGED_READ_IN_READ_SECRETS_ADDRESS){
        request_privilege();
    }

    uint32_t control = __get_CONTROL();
    printf("0x%.8x\n", control);

    flash_read(address, buffer, len);
    drop_privilege();
}

/**
 * @brief write to flash in privileged mode
 * @details if the return address is correct, switch to privileged mode, if not crash, if privilege mode is enabled,
 *          write to flash, and then drop privilege
 */
int flash_privileged_write(uint32_t address, void* buffer, uint32_t len) {
    void* return_addr = __builtin_return_address(0); 
    if ((return_addr == PRIVILEGED_WRITE_IN_UPDATE_SUBSCRIPTION_ADDRESS) 
        || (return_addr == PRIVILEGED_WRITE_IN_UPDATE_CURRENT_TIMESTAMP_ADDRESS )){
        request_privilege();
    }
    int error = flash_write(address, buffer, len);
    drop_privilege();
    return error;
}
