/**
 * @file status_led.h
 * @author Samuel Meyers
 * @brief eCTF Status LED Implementation
 * @date 2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#ifndef __STATUS_LED__
#define __STATUS_LED__

#include "led.h"

/* These macros may be used to control the RGB LED on the MAX78000 fthr boards*/

// reset LED state
#define STATUS_LED_OFF(void) LED_Off(LED1); LED_Off(LED2); LED_Off(LED3);

// Error state
#define STATUS_LED_RED(void) STATUS_LED_OFF(); LED_On(LED1);
// Waiting for message
#define STATUS_LED_GREEN(void) STATUS_LED_OFF(); LED_On(LED2);
#define STATUS_LED_BLUE(void) STATUS_LED_OFF(); LED_On(LED3);

// Decode command
#define STATUS_LED_PURPLE(void) STATUS_LED_OFF(); LED_On(LED1); LED_On(LED3);
// List command
#define STATUS_LED_CYAN(void) STATUS_LED_OFF(); LED_On(LED2); LED_On(LED3);
// Update command
#define STATUS_LED_YELLOW(void) STATUS_LED_OFF(); LED_On(LED1); LED_On(LED2);

#define STATUS_LED_WHITE(void) STATUS_LED_OFF(); LED_On(LED1); LED_On(LED2); LED_On(LED3);

// Error case alias
#define STATUS_LED_ERROR STATUS_LED_RED

#endif // __STATUS_LED__
