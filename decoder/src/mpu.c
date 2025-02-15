#include "mpu.h"
#include <stdint.h>

void SVC_Handler(void) {
    __set_CONTROL(__get_CONTROL() & ~0x1);
    __ISB();
}

void request_privilege() {
    __asm("svc #0");
}

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
