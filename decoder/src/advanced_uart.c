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
 * 
 *  @return The character read.  Otherwise see MAX78000 Error Codes for
 *      a list of return codes.
*/
int uart_readbyte(void){
    int data = MXC_UART_ReadCharacter(MAX_UARTn);
    return data;
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