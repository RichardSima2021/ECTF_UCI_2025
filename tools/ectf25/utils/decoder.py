"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

from dataclasses import dataclass
from enum import IntEnum
import struct
from typing import Optional, Iterator

from loguru import logger
from serial import Serial

MAGIC = b"%"
BLOCK_LEN = 256


class Opcode(IntEnum):
    """Enum class for use in device output processing."""

    DECODE = 0x44  # D
    SUBSCRIBE = 0x53  # S
    LIST = 0x4C  # L
    ACK = 0x41  # A
    DEBUG = 0x47  # G
    ERROR = 0x45  # E


NACK_MSGS = {Opcode.DEBUG, Opcode.ACK}


@dataclass
class MessageHdr:
    """Header for the Decoder protocol"""

    opcode: Opcode
    len: int

    @classmethod
    def parse(cls, stream: bytes) -> tuple["MessageHdr", bytes]:
        """Try to parse a stream of bytes into a MessageHdr

        :param stream: Stream of bytes to parse

        :returns: A tuple with the first parsable MesssageHdr and the remaining bytes
        """
        pre, magic, remainder = stream.partition(MAGIC)

        if magic != b"%":
            raise ValueError("No magic found")

        hdr, remainder = remainder[:3], remainder[3:]
        opc, ln = struct.unpack("<BH", hdr)
        return cls(Opcode(opc), ln), remainder

    def pack(self) -> bytes:
        """Pack the MessageHdr into bytes"""
        return MAGIC + struct.pack("<BH", self.opcode, self.len)


@dataclass
class Message:
    """Message for the Decoder protocol"""

    opcode: Opcode
    body: bytes

    @property
    def hdr(self) -> MessageHdr:
        """Get the header for the message"""
        return MessageHdr(self.opcode, len(self.body))

    def pack(self) -> bytes:
        """Pack the Message into bytes"""
        return self.hdr.pack() + self.body

    def packets(self) -> Iterator[bytes]:
        """An iterator that chunks the message into blocks to send to the Decoder. An
        ACK is expected from the Decoder after each block"""
        yield self.hdr.pack()
        for i in range(0, len(self.body), BLOCK_LEN):
            yield self.body[i : i + BLOCK_LEN]

    def is_ack(self) -> bool:
        """Returns whether the message is an ACK"""
        return self.opcode == Opcode.ACK


class DecoderError(Exception):
    pass


class DecoderIntf:
    """Standard asynchronous interface to the Decoder

    See https://rules.ectf.mitre.org/2025/getting_started/boot_reference
    """

    ACK = Message(Opcode.ACK, b"")

    def __init__(self, port, **serial_kwargs):
        """
        :param port: Serial port to the Decoder
        :param serial_kwargs: Args to pass to the serial interface construction
        """
        self.ser = Serial(baudrate=115200, **serial_kwargs)
        self.ser.port = port
        self.stream = b""

    def _open(self):
        """Open the serial connection if not already opened"""
        if not self.ser.is_open:
            self.ser.open()

    def decode(self, frame: bytes) -> bytes:
        """Decode a frame

        :param frame: An encoded frame to be decoded
        :returns: The decoded frame
        :raises DecoderError: Error on decode failure
        """
        # send decode message
        msg = Message(Opcode.DECODE, frame)
        self.send_msg(msg)

        # receive response
        resp = self.get_msg()
        if resp.opcode != Opcode.DECODE:
            raise DecoderError(f"Bad decode response {resp}")
        return resp.body

    def subscribe(self, subscription: bytes):
        """Subscribe the Decoder to a new subscription

        :param subscription: Content of subscription file created by
            ectf25_design.gen_subscription
        :raises DecoderError: Error on subscribe failure
        """
        # send subscribe message
        msg = Message(Opcode.SUBSCRIBE, subscription)
        self.send_msg(msg)

        # receive response
        resp = self.get_msg()
        if resp != Message(Opcode.SUBSCRIBE, b""):
            raise DecoderError(f"Bad subscribe response {resp}")

    def list(self) -> list[tuple[int, int, int]]:
        """List the subscribed channels of a Decoder

        :returns: A list of tuples containing the subscribed channels and start and end
            timestamps
        :raises DecoderError: Error on list failure
        """
        # send list message
        msg = Message(Opcode.LIST, b"")
        self.send_msg(msg)

        # receive response
        resp = self.get_msg()
        if resp.opcode != Opcode.LIST:
            raise DecoderError(f"Bad list response {resp}")

        # unpack number of channels
        nchannels, body = resp.body[:4], resp.body[4:]
        nchannels = struct.unpack("<I", nchannels)[0]
        logger.debug(f"Reported {nchannels} subscribed channels")

        # check for correct channels body size
        sz = struct.calcsize("<IQQ")
        expected = sz * nchannels
        if expected != len(body):
            raise DecoderError(
                f"Bad list response! Expected len {expected}, got {len(body)}"
            )

        # unpack channel infos
        channels = []
        for _ in range(nchannels):
            cbody, body = body[:sz], body[sz:]
            channel, start, end = struct.unpack("<IQQ", cbody)
            logger.debug(f"Found subscription for {channel} from {start} to {end}")
            channels.append((channel, start, end))

        return channels

    def send_ack(self):
        """Send an ACK to the Decoder"""
        self._open()
        self.ser.write(self.ACK.pack())

    def get_ack(self):
        """Get an expected ACK from the Decoder

        :raises DecoderError: Non-ACK response was received (other than DEBUGs)
        """
        msg = self.get_msg()
        if msg != self.ACK:
            logger.error(f"Got bad ACK {msg}")
            raise DecoderError(f"Got bad ACK {msg}")

    def try_parse(self) -> Optional[MessageHdr]:
        """Try to parse the input stream into a MessageHdr

        :returns: The MessageHdr if the parse was successful, None otherwise
        """
        try:
            hdr, self.stream = MessageHdr.parse(self.stream)
        except (ValueError, struct.error):
            return None
        logger.debug(f"Found header {hdr}")
        return hdr

    def get_raw_msg(self) -> Message:
        """Get a message, blocking until full message received

        :returns: Message received by Decoder
        :raises: DecoderError if unexpected behavior encountered
        """
        self._open()
        while (hdr := self.try_parse()) is None:
            b = self.ser.read(1)
            self.stream += b
        # Don't ACK an ACK or a debug message
        if hdr.opcode not in NACK_MSGS:
            self.send_ack()
        remaining = hdr.len
        body = b""
        while remaining > 0:
            block = b""
            while block_remaining := min(BLOCK_LEN, remaining) - len(block):
                block += self.ser.read(block_remaining)
            # Don't ACK an ACK or a debug message
            if hdr.opcode not in NACK_MSGS:
                self.send_ack()
            logger.debug(f"Read block {repr(block)}")
            body += block
            remaining -= len(block)
        msg = Message(hdr.opcode, body)
        logger.debug(f"Got message {msg}")
        return msg

    def get_msg(self) -> Message:
        """Get a message, handling DEBUG and ERROR messages

        :returns: Message received by Decoder, filtering DEBUGs
        :raises DecoderError: If unexpected behavior or ERROR message encountered
        """
        while True:
            msg = self.get_raw_msg()
            if msg.opcode == Opcode.ERROR:
                raise DecoderError(f"Decoder returned ERROR: {repr(msg.body)}")
            if msg.opcode != Opcode.DEBUG:
                return msg
            logger.info(f"Got DEBUG: {repr(msg.body)}")

    def send_msg(self, msg: Message):
        """Send a message to the Decoder

        :param msg: Message to send
        :raises DecoderError: If unexpected behavior or ERROR message encountered
        """
        self._open()
        for packet in msg.packets():
            logger.debug(f"Sending packet {packet}")
            self.ser.write(packet)
            self.get_ack()
