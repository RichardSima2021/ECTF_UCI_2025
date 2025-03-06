# Dockerfile for the 2025 eCTF
# Make any changes here to set up your build environment (e.g., installing crypto
# libraries, dependencies, the compiler for a different language)

FROM ubuntu:24.04

LABEL version="0.2"
LABEL description="Example Decoder Docker Container for the 2025 eCTF"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# Install Requisite Packages
# do this first because it takes the longest
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gdb \
    gdb-multiarch \
    gcc-arm-none-eabi \
    binutils-arm-none-eabi \
    make \
    python3.10 \
    python3-pip \
    python3-venv \
    git \
    wget \
    libtool \
    texinfo \
    unzip    \
    build-essential \
    libtool \
    autoconf \
    automake \
    && apt-get clean 

# Create and activate a virtual environment
RUN python3 -m venv my-venv

# Verify the virtual environment exists
RUN ls -l /root/my-venv/bin

# Upgrade pip inside the virtual environment
RUN /root/my-venv/bin/pip install --upgrade pip

# Install Python dependencies in the virtual environment
RUN /root/my-venv/bin/pip install pycryptodomex
    
# Install MSDK
RUN apt-get install -y unzip && \
    wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip && \
    unzip v2024_02.zip && \
    rm -f v2024_02.zip

ENV MAXIM_PATH=/root/msdk-2024_02

WORKDIR /decoder

ENTRYPOINT ["/bin/bash", "-c", "source /root/my-venv/bin/activate &&  make release DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]

# Sample run command:
# docker run -v ./decoder/:/decoder -v ./global.secrets:/global.secrets:ro -v ./deadbeef_build:/out -e DECODER_ID=0xdeadbeef build-decoder
