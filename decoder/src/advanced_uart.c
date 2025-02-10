/**
 * @file "advanced_uart.h"
 * @author Bug Eaters
 * @brief Advanced UART Interface Header 
 * @date 2025
 * @copyright UCI (2025)
 */

#include "advanced_uart.h"
#include "uart.h"



/** @brief Reads the next available character from UART.
 *  @param status Pointer to a status variable. See MAX78000 error codes for a list.
 *  @return The character read. If the status variable is set, this will be 0x00.
*/
uint8_t uart_readbyte(int* status) {
    uint8_t value;
    int data = MXC_UART_ReadCharacter(MAX_UARTn);
    if (data < 0) {
        *status = data;
        value = 0;
    } else {
        *status = 0;
        value = (uint8_t)data;
    }
    return value;
}

/**
 * @brief Writes a byte to UART.
 * @param data The byte to write.
 */
void uart_writebyte(uint8_t data) {
    while (MAX_UARTn->status & MXC_F_UART_STATUS_TX_FULL) {
    }
    MXC_UART_WriteCharacter(MAX_UARTn, data);
}

/** @brief Flushes UART.
*/
void uart_flush(void){
    MXC_UART_ClearRXFIFO(MAX_UARTn);
    MXC_UART_ClearTXFIFO(MAX_UARTn);
}