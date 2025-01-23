/**
 * @file "advanced_uart.h"
 * @author Bug Eaters
 * @brief Advanced UART Interface Header 
 * @date 2025
 * @copyright UCI (2025)
 */

#include "advanced_uart.h"
#include "uart.h"

#define MAX_UARTn MXC_UART_GET_UART(CONSOLE_UART)



/** @brief Reads the next available character from UART. Different from uard_readbyte_raw because
            it will wait until a character is ready. 
 * 
 *  @return The character read. Will return -1 on error.
*/
int uart_readbyte(void){
    int data = MXC_UART_ReadCharacter(CONSOLE_UART);
    return (char)data;
}

/**
 * @brief Writes a byte to UART.
 * @param data The byte to write.
 */
void uart_writebyte(uint8_t data) {
    while (MAX_UARTn->status & MXC_F_UART_STATUS_TX_FULL) {
    }
    MXC_UART_WriteCharacter(MXC_UARTn, data);
}

/** @brief Flushes UART.
*/
void uart_flush(void){
    MXC_UART_ClearRXFIFO(MAX_UARTn);
    MXC_UART_ClearTXFIFO(MAX_UARTn);
}