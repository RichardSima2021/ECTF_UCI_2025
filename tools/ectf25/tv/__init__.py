"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import binascii
import json
from queue import Queue
import socket
import threading
import time

from loguru import logger

from ectf25.utils.decoder import DecoderIntf


class DecoderError(Exception):
    """Error thrown by the Decoder"""

    pass


class TV:
    """Robust TV class for full end-to-end setup

    You can use ectf25.utils.tester for a lighter-weight development setup

    See https://rules.ectf.mitre.org/2025/getting_started/boot_reference
    """

    BLOCK_LEN = 256

    def __init__(self, sat_host: str, sat_port: int, dec_port: str, dec_baud: int):
        """
        :param sat_host: TCP host for the Satellite
        :param sat_port: TCP port for the Satellite
        :param dec_port: Serial port to the Decoder
        :param dec_baud: Baud rate of the Decoder serial interface
        """
        self.sat_host = sat_host
        self.sat_port = sat_port
        self.decoder = DecoderIntf(dec_port)
        self.to_decode = Queue()
        self.crash = threading.Event()

    def downlink(self):
        """Receive frames from the Satellite and queue them to be sent to the Decoder"""
        logger.info(f"Connecting to satellite at {self.sat_host}:{self.sat_port}")

        try:
            # Open connection to the Satellite
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.sat_host, self.sat_port))

            # Get frames forever
            while not self.crash.is_set():
                # Get and decode frame
                line = b""
                while not line.endswith(b"\n"):
                    if (cur_byte := s.recv(1)) == b"":  # connection closed
                        raise RuntimeError("Failed to receive from satellite")
                    line += cur_byte
                frame = json.loads(line)
                channel = frame["channel"]
                timestamp = frame["timestamp"]
                encoded = binascii.a2b_hex(frame.pop("encoded"))
                logger.debug(f"Received encoded ({channel}, {timestamp}): {encoded}")

                # Put frame in decode queue
                self.to_decode.put_nowait(encoded)
        except ConnectionRefusedError:
            logger.critical(
                f"Could not connect to Satellite at {self.sat_host}:{self.sat_port}"
            )
            self.crash.set()
        except Exception:
            logger.critical("Downlink crashed!")
            self.crash.set()
            raise

    def decode(self):
        """Serve frames from the queue to the Decoder, printing the decoded results"""
        logger.info("Starting Decoder loop")
        try:
            while not self.crash.is_set():
                if not self.to_decode.empty():
                    # Get an encoded frame from the queue
                    encoded = self.to_decode.get_nowait()

                    # Send the frame to be decoded
                    decoded = self.decoder.decode(encoded)

                    # Print the frame
                    try:
                        # if the frame contains printable text, pretty print it
                        logger.info(
                            (
                                b"\n"
                                + b"\n".join(
                                    [decoded[i : i + 8] for i in range(0, 64, 8)]
                                )
                            ).decode("utf-8")
                        )
                    except UnicodeDecodeError:
                        # if we can't decode bytes, fall back to just printing the frame
                        logger.info(decoded)
        except Exception:
            logger.critical("Decoder crashed!")
            self.crash.set()
            raise

    def run(self):
        """Run the TV, connecting to the Satellite and the Decoder"""

        try:
            decode = threading.Thread(target=self.decode)
            decode.start()
            downlink = threading.Thread(target=self.downlink, daemon=True)
            downlink.start()
            while downlink.is_alive() and decode.is_alive():
                # Main thread sleeps waiting for ctrl+c from user or threads to crash.
                # We have to busy wait here because if we decode.join(), the main thread
                # does not receive the KeyboardInterrupt exception. Main thread sleeps
                # to prevent using the CPU during the spin lock. The main thread will
                # still receive the keyboard interrupt in the sleep.
                time.sleep(0.1)
        except KeyboardInterrupt:  # expect exit from user
            pass
        finally:
            self.crash.set()
