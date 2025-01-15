"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import argparse

from loguru import logger

from ectf25.utils.decoder import DecoderIntf


def main():
    # Define and parse command line arguments
    parser = argparse.ArgumentParser(
        prog="ectf25.tv.subscribe",
        description="List the channels with a valid subscription on the Decoder",
    )
    parser.add_argument(
        "port",
        help="Serial port to the Decoder (see https://rules.ectf.mitre.org/2025/getting_started/boot_reference for platform-specific instructions)",
    )
    args = parser.parse_args()

    # Open Decoder interface
    decoder = DecoderIntf(args.port)

    # Run the list command
    subscriptions = decoder.list()

    # Print the results
    for channel, start, end in subscriptions:
        logger.info(f"Found subscription: Channel {channel} {start}:{end}")

    logger.success("List successful")


if __name__ == "__main__":
    main()
