/**
 * @file "advanced_uart.h"
 * @author Bug Eaters
 * @brief Advanced UART Interface Header 
 * @date 2025
 */
 
#ifndef __ADVANCED_UART__
#define __ADVANCED_UART__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "uart.h"
#include "nvic_table.h"
#include "board.h"

/******************************** MACRO DEFINITIONS ********************************/
#define UART_BAUD 115200

#define MAX_UARTn MXC_UART_GET_UART(CONSOLE_UART)

/******************************** FUNCTION PROTOTYPES ******************************/
/** @brief Initializes the UART Interrupt handler.
 * 
 *  @note This function should be called once upon startup.
 *  @return 0 upon success.  Negative if error.
*/
int uart_init(void);

/** @brief Reads a byte from UART and reports an error if the read fails.
 * 
 *  @return The character read.  Otherwise see MAX78000 Error Codes for
 *      a list of return codes. 
 *  @note maybe we should return a random error code to throw em off 
*/
int uart_readbyte_raw(void);

/** @brief Reads the next available character from UART.
 * 
 *  @return The character read.  Otherwise see MAX78000 Error Codes for
 *      a list of return codes.
 *  @note maybe we should return a random error code to throw em off 
*/
int uart_readbyte(void);

/** @brief Writes a byte to UART.
 * 
 *  @param data The byte to be written.
*/
void uart_writebyte(uint8_t data);

/** @brief Flushes UART.
*/
void uart_flush(void);

#endif // __ADVANCED_UART__
