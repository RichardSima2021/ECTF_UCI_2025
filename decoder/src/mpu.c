#include "mpu.h"
#include <stdint.h>
#include <stdio.h>

#include "host_messaging.h"


int update_subscription(pkt_len_t pkt_len, encrypted_update_packet *packet);
int update_current_timestamp(int channel_id, timestamp_t new_timestamp);
int read_secrets(int channel_id, secret_t* secret_buffer);

#define REQUEST_PRIVILEGE_IN_PRIVILEGED_READ_OFFSET (flash_privileged_read + 16) // placeholder
#define REQUEST_PRIVILEGE_IN_PRIVILEGED_WRITE_OFFSET (flash_privileged_write + 18) // placeholder

#define PRIVILEGED_READ_IN_READ_SECRETS_ADDRESS (read_secrets + 40) // TODO, placeholder currently

#define PRIVILEGED_WRITE_IN_UPDATE_SUBSCRIPTION_ADDRESS (update_subscription + 296) // TODO, placeholder

#define SVC_HANDLER_IN_REQUEST_PRIVILEGE_OFFSET (request_privilege + 22)

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

    int disabled_regions[] = {3, 4};
    int arr_size = 2;
    // Background Region
    MPU->RNR = 0;
    MPU->RBAR = MXC_ROM_MEM_BASE;
    MPU->RASR = (MPU_DEFS_RASR_SIZE_4GB | MPU_DEFS_NORMAL_MEMORY_WT | MPU_DEFS_RASE_AP_FULL_ACCESS | MPU_RASR_ENABLE_Msk | MPU_EXECUTION_DISABLE);
    //MPU->RASR = (MPU_DEFS_RASR_SIZE_4GB | MPU_DEFS_NORMAL_MEMORY_WT | MPU_DEFS_RASE_AP_NO_ACCESS | MPU_RASR_ENABLE_Msk);

    // // SRAM Flash Code Region
    MPU->RNR = 1;
    MPU->RBAR = MXC_SRAM_MEM_BASE;
    MPU->RASR = (MPU_DEFS_RASR_SIZE_32KB | MPU_DEFS_NORMAL_MEMORY_WT | MPU_DEFS_RASE_AP_FULL_ACCESS | MPU_RASR_ENABLE_Msk); // | MPU_EXECUTION_DISABLE);

    // FLASH TEXT Region
    MPU->RNR = 2;
    MPU->RBAR = MXC_FLASH_MEM_BASE;
    MPU->RASR = (MPU_DEFS_RASR_SIZE_256KB | MPU_DEFS_NORMAL_MEMORY_WT | MPU_DEFS_RASE_AP_RO | MPU_RASR_ENABLE_Msk);

    // Secrets Overlay Region
    MPU->RNR = 5;
    MPU->RBAR = MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE - 4 * MXC_FLASH_PAGE_SIZE;
    MPU->RASR = (MPU_DEFS_RASR_SIZE_32KB | MPU_DEFS_NORMAL_MEMORY_WT | MPU_DEFS_RASE_AP_NO_ACCESS | MPU_RASR_ENABLE_Msk | MPU_EXECUTION_DISABLE);

    // Decoder Status Region
    MPU->RNR = 6;
    MPU->RBAR = MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE - 2 * MXC_FLASH_PAGE_SIZE;
    MPU->RASR = (MPU_DEFS_RASR_SIZE_4KB | MPU_DEFS_NORMAL_MEMORY_WT | MPU_DEFS_RASE_AP_PRIV_RW_USER_RO | MPU_RASR_ENABLE_Msk | MPU_EXECUTION_DISABLE);

    // Secrets Region
    MPU->RNR = 7;
    MPU->RBAR = MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE - 3 * MXC_FLASH_PAGE_SIZE; 
    MPU->RASR = (MPU_DEFS_RASR_SIZE_4KB | MPU_DEFS_NORMAL_MEMORY_WT | MPU_DEFS_RASE_AP_PRIV_RO | MPU_RASR_ENABLE_Msk | MPU_EXECUTION_DISABLE);

    // Disable unused regions
    for (i = 0; i < arr_size; ++i) {
        MPU->RNR = disabled_regions[i];
        MPU->RBAR = 0;
        MPU->RASR = 0;
    }

    // Enable MPU
    Random_Delay();
    MPU->CTRL = MPU_CTRL_ENABLE_Msk;

    __DSB();
    __ISB();

    return 0;
}

/**
 * @brief SVC Handler
 * @details This function is called when an SVC interrupt is triggered. It clears the control bit for privileged mode.
 */
__attribute__((noinline))
void SVC_Handler(void) {
    __set_CONTROL(__get_CONTROL() & ~0x1);
    __ISB();

#ifdef CONDITIONAL_PRIV_ESCALATION_ENABLED
    __asm volatile(
        "TST lr, #4 \n"              // Test EXC_RETURN bit 2 (indicates which stack is used)
        "ITE EQ \n"
        "MRSEQ r0, MSP \n"           // If 0, use Main Stack Pointer (MSP)
        "MRSNE r0, PSP \n"           // If 1, use Process Stack Pointer (PSP)
        "B svc_handler_c \n"         // Branch to C handler
    );
#endif
} 

#ifdef CONDITIONAL_PRIV_ESCALATION_ENABLED
__attribute__((noinline))
void svc_handler_c(uint32_t *stack_frame) {
    void* return_addr = stack_frame[6];

    if ((return_addr+1) != SVC_HANDLER_IN_REQUEST_PRIVILEGE_OFFSET) {
        while(1);
    }
}
#endif

/**
 * @brief request privilege
 * @details This function checks if the return address is the flash_privileged_read function 
 *          if it is, it requests privilege by calling the SVC interrupt. It will crash if its not the correct return address.
 */
__attribute__((noinline))
void request_privilege() {
#ifdef CONDITIONAL_PRIV_ESCALATION_ENABLED
    void* return_addr = __builtin_return_address(0);

    if(return_addr != REQUEST_PRIVILEGE_IN_PRIVILEGED_READ_OFFSET &&
       return_addr != REQUEST_PRIVILEGE_IN_PRIVILEGED_WRITE_OFFSET){
        while (1);
       }
#endif
    __asm("svc #0");
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
 * @brief read from flash in privileged mode
 * @details if the return address is correct, switch to privileged mode, if not crash, if privilege mode is enabled,
 *          read from flash, and then drop privilege
 */
__attribute__((noinline))
void flash_privileged_read(uint32_t address, void *buffer, uint32_t len) {
#ifdef CONDITIONAL_PRIV_ESCALATION_ENABLED
    void* return_addr = __builtin_return_address(0);

    if(return_addr != PRIVILEGED_READ_IN_READ_SECRETS_ADDRESS) {
        while (1);
    }
#endif
    request_privilege();

    flash_read(address, buffer, len);
    drop_privilege();
}

/**
 * @brief write to flash in privileged mode
 * @details if the return address is correct, switch to privileged mode, if not crash, if privilege mode is enabled,
 *          write to flash, and then drop privilege
 */
__attribute__((noinline))
int flash_privileged_write(uint32_t address, void* buffer, uint32_t len) {
#ifdef CONDITIONAL_PRIV_ESCALATION_ENABLED
    void* return_addr = __builtin_return_address(0); 
    if ((return_addr != PRIVILEGED_WRITE_IN_UPDATE_SUBSCRIPTION_ADDRESS)){
        while (1);
    }
#endif
    request_privilege();
    int error = flash_write(address, buffer, len);
    drop_privilege();
    return error;
}
