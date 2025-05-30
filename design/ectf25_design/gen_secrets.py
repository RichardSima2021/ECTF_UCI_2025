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
import json
import os
# from ectf25_design import generate_secret_h #as generate_secret_h
from pathlib import Path

import secrets as secret_gen
from loguru import logger

def gen_secrets(channels: list[int]) -> bytes:
    """Generate the contents secrets file

    This will be passed to the Encoder, ectf25_design.gen_subscription, and the build
    process of the decoder

    :param channels: List of channel numbers that will be valid in this deployment.
        Channel 0 is the emergency broadcast, which will always be valid and will
        NOT be included in this list

    :returns: Contents of the secrets file
    """
    # TODO: Update this function to generate any system-wide secrets needed by
    #   your design

    # Create the secrets object
    # You can change this to generate any secret material
    # The secrets file will never be shared with attackers
    # secrets = {
    #     "channels": channels,
    #     "some_secrets": "EXAMPLE",
    # }
    
    if 0 not in channels:
        channels = [0] + channels

    secrets = {
        # creates a new list with the value 0, representing channel 0, 
        # as the first element
        "channels": channels,
    }
    secrets['flash_key']=os.urandom(16).hex()

    # print('Flash key: ', secrets['flash_key'])
    
    for channel in channels:
        secrets[f"channel_{channel}"] = {
            "channel_ID": str(channel),  # Channel ID as an integer
            "mask_key": os.urandom(16).hex(),  # 16 bytes hex
            "msg_key": os.urandom(16).hex(),   # 16 bytes hex
            "data_key": os.urandom(16).hex(),  # 16 bytes hex
            "subscription_key": os.urandom(16).hex(),  # 16 bytes
            "check_sum": os.urandom(20).hex(),  # 20 bytes - first four bytes of sub_info (channel_id) will not be encrypted
        }


    # NOTE: if you choose to use JSON for your file type, you will not be able to
    # store binary data, and must either use a different file type or encode the
    # binary data to hex, base64, or another type of ASCII-only encoding
    return json.dumps(secrets).encode()


def parse_args():
    """Define and parse the command line arguments

    NOTE: Your design must not change this function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "channels",
        nargs="+",
        type=int,
        help="Supported channels. Channel 0 (broadcast) is always valid and will not"
        " be provided in this list",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets

    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    secrets = gen_secrets(args.channels)

    # Print the generated secrets for your own debugging
    # Attackers will NOT have access to the output of this, but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    logger.debug(f"Generated secrets: {secrets}")

    # Open the file, erroring if the file exists unless the --force arg is provided

    # To put the secrets.json file in the secrets directory when generating the json file, prepend "../../secrets"
    # the name of your json file. Example: python gen_secrets.py ../../secrets/secrets.json 1 2 3
    with open(args.secrets_file, "wb") as f:
        # Dump the secrets to the file
        f.write(secrets)
    
    # generate_secret_h.gen_sec(args.secrets_file)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()
