"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

from loguru import logger


class _Encoder:
    """Fallback Encoder class used if ectf25_design isn't installed

    THIS IS ONLY USED WHEN THE SETUP IS INCORRECT
    """

    def __init__(self, secrets: bytes):
        logger.warning(
            "\nCould not find ectf_encoder.Encoder! Make sure ectf25_design has been"
            " pip-installed to this python with:"
            f"\n\t{sys.executable} -m pip install ./design"
            "\nFrom the root of the repository."
            "\n\nUsing default fallback encoder"
        )

    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        logger.warning(
            "\nCould not find ectf_encoder.Encoder! Make sure ectf25_design has been"
            " pip-installed to this python with:"
            f"\n\t{sys.executable} -m pip install ./design"
            "\nFrom the root of the repository."
            "\n\nUsing default fallback encoder"
        )
        return frame


try:
    from ectf25_design.encoder import Encoder
except ImportError:
    import sys

    logger.warning(
        "\nCould not find ectf_encoder.Encoder! Make sure ectf25_design has been"
        " pip-installed to this python with:"
        f"\n\t{sys.executable} -m pip install ./design"
        "\nFrom the root of the repository."
        "\n\nUsing default fallback encoder"
    )
    Encoder = _Encoder
