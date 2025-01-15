/**
 * @file host_messaging.h
 * @author Samuel Meyers
 * @brief eCTF Host Messaging Implementation 
 * @date 2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#ifndef __HOST_MESSAGING__
#define __HOST_MESSAGING__

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include "simple_uart.h"

#define CMD_TYPE_LEN sizeof(char)
#define CMD_LEN_LEN sizeof(uint16_t)
#define MSG_MAGIC '%'     // '%' - 0x25

typedef enum {
    DECODE_MSG = 'D',     // 'D' - 0x44
    SUBSCRIBE_MSG = 'S',  // 'S' - 0x53
    LIST_MSG = 'L',       // 'L' - 0x4c
    ACK_MSG = 'A',        // 'A' - 0x41
    DEBUG_MSG = 'G',      // 'G' - 0x47
    ERROR_MSG = 'E',      // 'E' - 0x45
} msg_type_t;

#pragma pack(push, 1) // Tells the compiler not to pad the struct members
typedef struct {
    char magic;    // Should be MSG_MAGIC
    char cmd;      // msg_type_t
    uint16_t len;
} msg_header_t;

#pragma pack(pop) // Tells the compiler to resume padding struct members

#define MSG_HEADER_SIZE sizeof(msg_header_t)

/** @brief Write len bytes to UART in hex. 2 bytes will be printed for every byte.
 * 
 *  @param type Message type.
 *  @param buf Pointer to the bytes that will be printed.
 *  @param len The number of bytes to print.
 * 
 *  @return 0 on success. A negative value on error.
*/
int write_hex(msg_type_t type, const void *buf, size_t len);

/** @brief Send a message to the host, expecting an ack after every 256 bytes.
 * 
 *  @param type The type of message to send.
 *  @param buf Pointer to a buffer containing the outgoing packet.
 *  @param len The size of the outgoing packet in bytes.
 * 
 *  @return 0 on success. A negative value on failure.
*/
int write_packet(msg_type_t type, const void *buf, uint16_t len);

/** @brief Reads a packet from console UART.
 * 
 *  @param cmd A pointer to the resulting opcode of the packet. Must not be null.
 *  @param buf A pointer to a buffer to store the incoming packet. Can be null.
 *  @param len A pointer to the resulting length of the packet. Can be null.
 * 
 *  @return 0 on success, a negative number on failure
*/
int read_packet(msg_type_t* cmd, void *buf, uint16_t *len);

// Macro definitions to print the specified format for error messages
#define print_error(msg) write_packet(ERROR_MSG, msg, strlen(msg))

// Macro definitions to print the specified format for debug messages
#define print_debug(msg) write_packet(DEBUG_MSG, msg, strlen(msg))
#define print_hex_debug(msg, len) write_hex(DEBUG_MSG, msg, len)

// Macro definitions to write ack message
#define write_ack() write_packet(ACK_MSG, NULL, 0)

#endif
