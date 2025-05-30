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
import struct
import json
import secrets as secret_gen
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256



class Encoder:
    def __init__(self, secrets: bytes):
        """
        You **may not** change the arguments or returns of this function!

        :param secrets: Contents of the secrets file generated by
            ectf25_design.gen_secrets
        """
        # TODO: parse your secrets data here and run any necessary pre-processing to
        #   improve the throughput of Encoder.encode

        # Load the json of the secrets file
        secrets = json.loads(secrets)

        # Load the example secrets for use in Encoder.encode
        # This will be "EXAMPLE" in the reference design"
        self.channels = secrets["channels"]

        self.channel_keys = {}

        for channel in self.channels:
            self.channel_keys[f'channel_{channel}'] = secrets[f'channel_{channel}']


    def XOR(self, byte1, byte2):
        """XOR two bytes"""
        # Extend them two same length
        if len(byte1) < len(byte2):
            byte = byte1
            byte1 = byte2
            byte2 = byte
        byte2 = byte2.ljust(len(byte1), b'\x00')
        return bytes(a ^ b for a, b in zip(byte1, byte2))

    
    def sym_encrypt(self, key, iv, plaintext):
        """Encrypt plaintext using AES"""

        aes = AES.new(key, AES.MODE_CBC, iv)
        return aes.encrypt(plaintext)
    
    def sym_decrypt(self, key, iv, ciphertext):
        aes = AES.new(key, AES.MODE_CBC, iv)
        return aes.decrypt(ciphertext)
    
    def compute_hash(self, data):
        """Compute the SHA-256 hash of the data"""
        hash = SHA256.new()
        hash.update(data)
        return hash.digest()
    
    def pad(self, data, block_size):
        """Pad the data to the block size"""
        assert type(data) == bytes, "Data must be bytes"
        extra = len(data) % block_size
        if extra == 0:
            padding_length = 0
        else:
            padding_length = block_size - extra
        return data + b'\x00' * padding_length



    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        """The frame encoder function

        This will be called for every frame that needs to be encoded before being
        transmitted by the satellite to all listening TVs

        You **may not** change the arguments or returns of this function!

        :param channel: 32b unsigned channel number. Channel 0 is the emergency
            broadcast that must be decodable by all channels.
        :param frame: Frame to encode. Max frame size is 64 bytes.
        :param timestamp: 64b timestamp to use for encoding. **NOTE**: This value may
            have no relation to the current timestamp, so you should not compare it
            against the current time. The timestamp is guaranteed to strictly
            monotonically increase (always go up) with subsequent calls to encode

        :returns: The encoded frame, which will be sent to the Decoder
        """
        # TODO: encode the satellite frames so that they meet functional and
        #  security requirements

        if f'channel_{channel}' not in self.channel_keys:
            return struct.pack("<IQI", channel, timestamp, len(frame))
    

        mask_key = bytes.fromhex(self.channel_keys[f'channel_{channel}']["mask_key"])
        msg_key = bytes.fromhex(self.channel_keys[f'channel_{channel}']["msg_key"])
        subscription_key = bytes.fromhex(self.channel_keys[f'channel_{channel}']["subscription_key"])
        data_key = bytes.fromhex(self.channel_keys[f'channel_{channel}']["data_key"])

    
        # Check the key are all 16 bytes long
        assert len(mask_key) == 16, "The mask key is not 16 bytes long"
        assert len(msg_key) == 16, "The message key is not 16 bytes long"
        assert len(subscription_key) == 16, "The subscription key is not 16 bytes long"
        assert len(data_key) == 16, "The data key is not 16 bytes long"

        nounce = secret_gen.token_bytes(16)
        iv = secret_gen.token_bytes(16)
        
        # Prepare C1 info
        timestamp_prime = nounce[:8] + timestamp.to_bytes(8, 'little') + nounce[8:]

        c1_key = self.XOR((self.compute_hash(self.XOR(mask_key, timestamp.to_bytes(8, 'little')))), (msg_key))
        c1_key = c1_key[:16]
        c1_data = self.pad(timestamp_prime, 16)
        c1 = self.sym_encrypt(c1_key, iv, c1_data)

        # Prepare C2 info
        c2_key = self.XOR(nounce, data_key)
        c2_data = self.pad(frame, 16)
        c2 = self.sym_encrypt(c2_key, iv, c2_data)

        frame_size = len(frame)

        return struct.pack("<IQI", channel, timestamp, frame_size) + iv + c1 + c2
    


def main():
    """A test main to one-shot encode a frame

    This function is only for your convenience and will not be used in the final design.

    After pip-installing, you should be able to call this with:
        python3 -m ectf25_design.encoder path/to/test.secrets 1 "frame to encode" 100
    """
    parser = argparse.ArgumentParser(prog="ectf25_design.encoder")
    parser.add_argument(
        "secrets_file", type=argparse.FileType("rb"), help="Path to the secrets file"
    )
    parser.add_argument("channel", type=int, help="Channel to encode for")
    parser.add_argument("frame", help="Contents of the frame")
    parser.add_argument("timestamp", type=int, help="64b timestamp to use")
    args = parser.parse_args()

    encoder = Encoder(args.secrets_file.read())
    print(repr(encoder.encode(args.channel, args.frame.encode(), args.timestamp)))


if __name__ == "__main__":
    main()
