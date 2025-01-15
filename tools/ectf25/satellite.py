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
import asyncio
from asyncio import StreamWriter, StreamReader, Future, TaskGroup, Lock
from dataclasses import dataclass
import json

from loguru import logger


class PubSub:
    """PubSub
    Publisher-Subscriber class. A call to publish will broadcast the message
    to all subscribers awaiting on subscribe
    """

    def __init__(self):
        self.waiter = Future()

    def publish(self, value):
        waiter, self.waiter = self.waiter, Future()
        waiter.set_result((value, self.waiter))

    async def subscribe(self):
        waiter = self.waiter
        while True:
            value, waiter = await waiter
            yield value

    __aiter__ = subscribe


@dataclass
class Channel:
    number: int
    down_host: str
    down_port: int

    def __post_init__(self):
        self.pubsub = PubSub()


class Satellite:
    """Robust Satellite class to broadcast frames from the Uplink to any number of
    receivers for the full end-to-end setup

    You can use ectf25.utils.tester for a lighter-weight development setup
    """

    def __init__(
        self,
        channels: dict[int, Channel],
        up_host: str,
        up_port: int,
    ):
        """
        :param channels: List of channels to serve on
        :param up_host: Hostname for uplink
        :param up_port: Port for uplink
        """
        self.channels = channels
        self.port_to_channels = {
            channel.down_port: channel for channel in self.channels.values()
        }
        self.up_host = up_host
        self.up_port = up_port
        self.cleanup_tasks: list[asyncio.Task] = []
        self.streams: set[asyncio.StreamWriter] = set()
        self.encoder_lock = Lock()

    async def downlink(self, _, writer: StreamWriter):
        """Handles the downlink for one TV on one channel"""
        self.streams.add(writer)
        port = writer.transport.get_extra_info("sockname")[1]
        peer = writer.transport.get_extra_info("peername")
        try:
            channel = self.port_to_channels[port]
            logger.info(f"{peer} Downlink opened on channel {channel.number}")
            async for message in channel.pubsub:
                writer.write(message)
                await writer.drain()
        except ConnectionResetError:
            pass
        finally:
            logger.warning(f"{peer} Downlink closed")
            self.streams.discard(writer)

    async def serve_uplink(self, reader: StreamReader, _):
        """Serve uplink connections"""
        try:
            while True:
                raw_frame = await reader.readline()
                frame = json.loads(raw_frame.decode())
                channel = frame["channel"]
                if channel == 0:
                    for c in self.channels.values():
                        c.pubsub.publish(raw_frame)
                elif channel in self.channels:
                    self.channels[channel].pubsub.publish(raw_frame)
                else:
                    raise ValueError(
                        f"Bad channel {channel} (expected {list(self.channels)})"
                    )
                await asyncio.sleep(0)
        except json.JSONDecodeError:
            logger.critical("Uplink read fail!")
        finally:
            logger.critical("Uplink ended unexpectedly!")
            self.handle_fatal()

    async def serve_downlink(self, channel: Channel):
        """Serve downlink connections"""
        host = channel.down_host
        port = channel.down_port
        server = await asyncio.start_server(self.downlink, host, port)
        try:
            async with server:
                logger.info(f"Serving downlink channel {channel} at {(host, port)}")
                async with TaskGroup() as tg:
                    task = tg.create_task(server.serve_forever())
                    self.cleanup_tasks.append(task)
        finally:
            logger.critical(f"Downlink server {channel.number} ended unexpectedly!")
            self.handle_fatal()

    def handle_fatal(self):
        """Cleanup tasks and streams on a fatal error"""
        for task in self.cleanup_tasks:
            task.cancel()
        for stream in self.streams:
            stream.close()

    async def serve(self):
        """Base satellite server loop"""
        try:
            logger.info(f"Connecting to uplink on {self.up_host}:{self.up_port}")
            reader, writer = await asyncio.open_connection(self.up_host, self.up_port)
        except OSError:
            logger.critical(
                f"Could not connect to uplink on {self.up_host}:{self.up_port}"
            )
            return

        logger.info(f"Serving channels {self.channels}")
        async with TaskGroup() as tg:
            tg.create_task(self.serve_uplink(reader, writer), name="uplink")
            for number, channel in self.channels.items():
                tg.create_task(
                    self.serve_downlink(channel),
                    name=f"downlink{number}",
                )
        logger.critical("Satellite ended unexpectedly!")


def channel_ty(arg: str):
    try:
        channel, down_port = arg.split(":")
        return int(channel), int(down_port)
    except ValueError:
        logger.critical(f'Bad channel "{arg}"! Should be `channel:port`')
        raise


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("up_host", help="Hostname for uplink")
    parser.add_argument("up_port", help="Port for uplink")
    parser.add_argument("down_host", help="Hostname for downlink")
    parser.add_argument(
        "channels",
        nargs="+",
        type=channel_ty,
        help="List of channel:down_port pairings (e.g., 1:2001 2:2002)",
    )
    args = parser.parse_args()

    channels = {
        number: Channel(number, args.down_host, port) for number, port in args.channels
    }
    satellite = Satellite(channels, args.up_host, args.up_port)
    await satellite.serve()

    # should only reach here on crash
    exit(-1)


if __name__ == "__main__":
    asyncio.run(main())
