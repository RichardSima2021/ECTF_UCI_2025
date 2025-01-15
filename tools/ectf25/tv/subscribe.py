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
        description="Subscribe a Decoder to a new subscription",
    )
    parser.add_argument(
        "subscription_file",
        type=argparse.FileType("rb"),
        help="Path to the subscription file created by ectf25_design.gen_subscription",
    )
    parser.add_argument(
        "port",
        help="Serial port to the Decoder (see https://rules.ectf.mitre.org/2025/getting_started/boot_reference for platform-specific instructions)",
    )
    args = parser.parse_args()

    # Read subscription file
    subscription = args.subscription_file.read()

    # Open Decoder interface
    decoder = DecoderIntf(args.port)

    # Run subscribe command
    decoder.subscribe(subscription)

    logger.success("Subscribe successful")


if __name__ == "__main__":
    main()
