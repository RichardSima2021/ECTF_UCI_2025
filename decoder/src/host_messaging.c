/**
 * @file host_messaging.c
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

#include <stdio.h>

#include "host_messaging.h"


/** @brief Read len bytes from UART, acknowledging after every 256 bytes.
 * 
 *  @param buf Pointer to a buffer where the incoming bytes should be stored.
 *  @param len The number of bytes to be read.
 * 
 *  @return 0 on success. A negative value on error.
*/
int read_bytes(void *buf, uint16_t len) {
    int result;
    int i;

    for (i = 0; i < len; i++) {
        if (i % 256 == 0 && i != 0) { // Send an ACK after receiving 256 bytes
            write_ack();
        }
        result = uart_readbyte();
        if (result < 0) {  // if there was an error, return immediately
            return result;
        }
        ((uint8_t *)buf)[i] = result;
    }

    return 0;
}

/** @brief Read a msg header from UART.
 * 
 *  @param hdr Pointer to a buffer where the incoming bytes should be stored.
*/
void read_header(msg_header_t *hdr) {
    hdr->magic = uart_readbyte();
    // Any bytes until '%' will be read, but ignored.
    // Once we receive a '%', continue with processing the rest of the message.
    while (hdr->magic != MSG_MAGIC) {
        hdr->magic = uart_readbyte();
    }
    hdr->cmd = uart_readbyte();
    read_bytes(&hdr->len, sizeof(hdr->len));
}

/** @brief Receive an ACK from UART.
 * 
 *  @return 0 on success. A negative value on error.
*/
uint8_t read_ack() {
    msg_header_t ack_buf = {0};

    read_header(&ack_buf);
    if (ack_buf.cmd == ACK_MSG) {
        return 0;
    } else {
        return -1;
    }
}

/** @brief Write len bytes to console
 * 
 *  @param buf Pointer to a buffer that stores the outgoing bytes.
 *  @param len The number of bytes to write.
 *  @param should_Ack True if the decoder should expect an ACK. This should be false for
 *                    debug and ACK messages.
 * 
 *  @return 0 on success. A negative value on error.
*/
int write_bytes(const void *buf, uint16_t len, bool should_ack) {
    for (int i = 0; i < len; i++) {
        if (i % 256 == 0 && i != 0) {  // Expect an ACK after sending every 256 bytes
            if (should_ack && read_ack() < 0) {
                return -1;
            }
        }
        uart_writebyte(((uint8_t *)buf)[i]);
    }

    fflush(stdout);

    return 0;
}

/** @brief Write len bytes to UART in hex. 2 bytes will be printed for every byte.
 * 
 *  @param type Message type.
 *  @param buf Pointer to the bytes that will be printed.
 *  @param len The number of bytes to print.
 * 
 *  @return 0 on success. A negative value on error.
*/
int write_hex(msg_type_t type, const void *buf, size_t len) {
    msg_header_t hdr;
    int i;

    hdr.magic = MSG_MAGIC;
    hdr.cmd = type;
    hdr.len = len*2;

    write_bytes(&hdr, MSG_HEADER_SIZE, false /* should_ack */);
    if (type != DEBUG_MSG && read_ack() < 0) {
        // If the header was not ack'd, don't send the message
        return -1;
    }

    for (i = 0; i < len; i++) {
        if (i % (256 / 2) == 0 && i != 0) {
            if (type != DEBUG_MSG && read_ack() < 0) {
                // If the block was not ack'd, don't send the rest of the message
                return -1;
            }
        }
    	printf("%02x", ((uint8_t *)buf)[i]);
        fflush(stdout);
    }
    return 0;
}

/** @brief Send a message to the host, expecting an ack after every 256 bytes.
 * 
 *  @param type The type of message to send.
 *  @param buf Pointer to a buffer containing the outgoing packet.
 *  @param len The size of the outgoing packet in bytes.
 * 
 *  @return 0 on success. A negative value on failure.
*/
int write_packet(msg_type_t type, const void *buf, uint16_t len) {
    msg_header_t hdr;
    int result;

    hdr.magic = MSG_MAGIC;
    hdr.cmd = type;
    hdr.len = len;

    result = write_bytes(&hdr, MSG_HEADER_SIZE, false);
    if (type == ACK_MSG) {
        return result;
    }

    // If the header was not ack'd, don't send the message
    if (type != DEBUG_MSG && read_ack() < 0) {
        return -1;
    }
    // If there is data to write, write it
    if (len > 0) {
        result = write_bytes(buf, len, type != DEBUG_MSG);
        // If we still need to ACK the last block (write_bytes does not handle the final ACK)
        if (type != DEBUG_MSG && read_ack() < 0) {
            return -1;
        }
    }

    return 0;
}

/** @brief Reads a packet from console UART.
 * 
 *  @param cmd A pointer to the resulting opcode of the packet. Must not be null.
 *  @param buf A pointer to a buffer to store the incoming packet. Can be null.
 *  @param len A pointer to the resulting length of the packet. Can be null.
 * 
 *  @return 0 on success, a negative number on failure
*/
int read_packet(msg_type_t* cmd, void *buf, uint16_t *len) {
    msg_header_t header = {0};

    // cmd must be a valid pointer
    if (cmd == NULL) {
        return -1;
    }

    read_header(&header);

    *cmd = header.cmd;

    if (len != NULL) {
        *len = header.len;
    }

    if (header.cmd != ACK_MSG) {
        write_ack();  // ACK the header
        if (header.len && buf != NULL) {
            if (read_bytes(buf, header.len) < 0) {
                return -1;
            }
        }
        if (header.len) {
            if (write_ack() < 0) { // ACK the final block (not handled by read_bytes)
                return -1;
            }
        }
    }
    return 0;
}
