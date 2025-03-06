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
#include <stdbool.h>
#include "types.h"


#define FREQUENCY_CHECKING_ENABLED (1)


/** @brief Read len bytes from UART, acknowledging after every 256 bytes.
 * 
 *  @param buf Pointer to a buffer where the incoming bytes should be stored.
 *  @param len The number of bytes to be read.
 * 
 *  @return 0 on success. A negative value on error.
*/
int read_bytes(void *buf, uint16_t len) {
    int status;
    uint8_t result;
    int i;

    for (i = 0; i < len; i++) {
        // Never expect to ACK since the max length is 124 bytes
        // if (i % 256 == 0 && i != 0) { // Send an ACK after receiving 256 bytes
        //     write_ack();
        // }
        result = uart_readbyte(&status);
        if (status < 0) {  // if there was an error, return immediately
            return result;
        }
        if (i >= BUF_LEN) return -1;
        ((uint8_t *)buf)[i] = result;
    }
    return 0;
}

/** @brief Read a msg header from UART.
 * 
 *  @param hdr Pointer to a buffer where the incoming bytes should be stored.
*/
void read_header(msg_header_t *hdr) {
    int status;

    hdr->magic = (char)0;
    // Any bytes until '%' will be read, but ignored.
    // Once we receive a '%', continue with processing the rest of the message.
    while (hdr->magic != MSG_MAGIC) {
        hdr->magic = uart_readbyte(&status);
        // hardfaults on E_OVERFLOW (status = -13) error
        volatile int x = 5 / (13 + status); // NOTE: Remove this if we hardfault
        // if (status < 0) {
        //     // underflow error
        //     // see MXC_UART_RevB_ReadCharacterRaw
        // }
    }
    hdr->cmd = uart_readbyte(&status);
    volatile int x = 5 / (13 + status); // see above

    read_bytes(&hdr->len, 2); // sizeof(&hdr->len) always 2
    //  write_ack(); // ACK the final block

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
        if (i >= BUF_LEN) return -1;
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



/*********************************************** Frequency Check ***************************************************************/
#define BYTE_RANGE 256  // 256 possible byte values (0x00 - 0xFF)

// Function to compute hex byte frequency from a space-separated string
void get_hex_freq_from_buffer(const unsigned char *buf, size_t length, double output[]) {
    int count[BYTE_RANGE] = {0};  // Byte occurrence counter
    int total_bytes = 0;

    // Process each byte in the buffer
    for (size_t i = 0; i < length; i++) {
        count[buf[i]]++;  // Increment count for the byte
        total_bytes++;
    }

    // Compute relative frequencies
    for (int i = 0; i < BYTE_RANGE; i++) {
        output[i] = (total_bytes == 0) ? 0.0 : ((double)count[i] / total_bytes);
    }
}

double calculate_mic(const double freq_A[], const double freq_B[]) {
    double mic = 0.0;
    // Sum of the product of the two distributions
    for (int i = 0; i < BYTE_RANGE; i++) {
        mic += freq_A[i] * freq_B[i];
    }
    return mic;
}


// Function to print the frequencies of hex bytes
void print_hex_frequencies(double output[]) {
    printf("Hex Byte Frequencies:\n");
    for (int i = 0; i < BYTE_RANGE; i++) {
        if (output[i] > 0) {  // Print only non-zero frequencies
            printf("0x%02X: %.6lf\n", i, output[i]);
        }
    }
}

int check_frequency(void* buffer) {
#ifdef FREQUENCY_CHECKING_ENABLED
    double arm_freq[BYTE_RANGE] = {0.098184,0.029423,0.016444,0.016026,0.016503,0.008202,0.008720,0.011805,0.014393,0.005853,0.004997,0.004698,
    0.008600,0.004161,0.004758,0.005037,0.017917,0.002588,0.002807,0.003922,0.002767,0.001573,0.001533,0.001732,0.003743,0.002289,0.003922,
    0.003344,0.003444,0.001513,0.001493,0.001553,0.022635,0.004698,0.007027,0.010332,0.002409,0.001513,0.001971,0.000876,0.008401,0.005514,
    0.004201,0.009058,0.002011,0.002648,0.002747,0.001792,0.009715,0.002269,0.002827,0.004141,0.002170,0.001115,0.001155,0.000597,0.003384,
    0.001155,0.000975,0.003464,0.001573,0.001214,0.000916,0.001712,0.010014,0.003544,0.007346,0.006092,0.005415,0.003006,0.033505,0.004997,
    0.002926,0.002747,0.001194,0.005057,0.002170,0.001413,0.000876,0.007326,0.003763,0.001573,0.002110,0.003484,0.001652,0.001334,0.000756,
    0.000577,0.001613,0.000856,0.000956,0.001991,0.001175,0.000657,0.000617,0.001294,0.008102,0.002628,0.002110,0.002469,0.002050,0.002130,
    0.001035,0.000916,0.008799,0.003782,0.001234,0.001613,0.002150,0.001175,0.002090,0.002688,0.006351,0.000438,0.001513,0.002269,0.001155,
    0.001135,0.000637,0.000538,0.002150,0.000677,0.000936,0.000637,0.000438,0.000338,0.000816,0.003484,0.007724,0.004081,0.002449,0.003583,
    0.001931,0.001473,0.000697,0.000557,0.001194,0.001453,0.000617,0.000956,0.000836,0.001971,0.000796,0.001314,0.003364,0.003145,0.003603,
    0.009436,0.001931,0.000796,0.000956,0.000498,0.003942,0.003603,0.004499,0.008282,0.001871,0.001652,0.000916,0.000717,0.001652,0.000836,
    0.000756,0.002628,0.000836,0.000617,0.000776,0.000458,0.001712,0.001394,0.002807,0.001871,0.002528,0.001712,0.001453,0.000956,0.003623,
    0.003006,0.002588,0.001314,0.001593,0.002807,0.000677,0.000199,0.001772,0.002190,0.001891,0.002369,0.000995,0.005873,0.000418,0.007923,
    0.002289,0.000717,0.000956,0.001075,0.001035,0.000776,0.000378,0.000398,0.002907,0.000995,0.000896,0.000657,0.000478,0.003245,0.000279,
    0.000179,0.005773,0.005196,0.001254,0.001652,0.002230,0.001712,0.000478,0.000219,0.002150,0.001891,0.001155,0.001334,0.001394,0.005375,
    0.000677,0.001194,0.002966,0.000796,0.000498,0.000577,0.001632,0.002289,0.002230,0.008720,0.002588,0.007804,0.006868,0.005992,0.000776,
    0.000617,0.001394,0.001752,0.032091,0.012960,0.002787,0.004101,0.006251,0.002210,0.000876,0.009357,0.022914,0.003603,0.004798,0.003763,
    0.002289,0.002528,0.005176,0.012104};
    // unsigned char buffer[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64};
    // unsigned char buffer[] = {0x30, 0xb5, 0x4f, 0xf0, 0x80, 0x54, 0x0b, 0x4d, 0x20, 
    // 0x00, 0xa8, 0x42, 0x83, 0xb0, 0x0d, 0xd8, 0x01, 0x22, 0x0d, 0xf1, 0x07, 0x01, 
    // 0x00, 0xf0, 0xc3, 0xfe, 0x9d, 0xf8, 0x07, 0x00, 0x03, 0xf0, 0xff, 0xf9, 0x20, 
    // 0x00, 0x01, 0x30, 0xa8, 0x42, 0x04, 0x00, 0xf1, 0xd9, 0x00, 0x20, 0x03, 0xb0, 
    // 0x30, 0xbd};
    size_t buffer_size = sizeof(buffer);

    double freq[BYTE_RANGE] = {0.0};

    get_hex_freq_from_buffer(buffer, buffer_size, freq);
    print_hex_frequencies(freq);

    double mic = calculate_mic(arm_freq, freq);
    if (mic > 0.009) {
        //printf("MIC: %.6lf ARM Code\n", mic);
        return 0;
        
    } else {
        //printf("MIC: %.6lf Normal Frame\n", mic);
        return 1;
    }
    return 0;
    
#else
    return 1;
}

/*******************************************************************************************************************/


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

    if (cmd == DECODE_MSG && *len > 128) {
        return -1; // Reject packets larger than 124 bytes, invalid lengths are not handled
    } else if (cmd == SUBSCRIBE_MSG && *len > 68) {
        return -1; // Reject packets larger than 68 bytes, invalid lengths are not handled
    } else if (cmd == LIST_MSG && *len != 0) {
        return -1; // Reject packets larger than 0 bytes, invalid lengths are not handled
    }

    if (header.cmd != ACK_MSG) {
        write_ack();  // ACK the header
        if (*len && buf != NULL) {
            // Read the data
            if (read_bytes(buf, header.len) < 0) {
                return -1;
            }
        }
        if (*len) {
            if (write_ack() < 0) { // ACK the final block (not handled by read_bytes)
                return -1;
            }
        }
    }
    uart_flush_rx(); // Flush any remaining bytes in the UART recieve buffer
    return 0;
}
