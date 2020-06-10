#!/bin/bash
set -ex

sudo apt-get update
sudo apt-get install -y \
    build-essential \
    curl wget rsync pv \
    make gcc g++ bc python xutils-dev flex bison autogen libgcrypt20-dev libjson-c-dev \
    autopoint pkgconf autoconf libtool libcurl4-openssl-dev libprotobuf-dev libprotobuf-c-dev protobuf-compiler protobuf-c-compiler libssl-dev \
    ninja-build ansible linux-headers-$(uname -r) \
    python3-venv unzip dkms debhelper apt-utils pax-utils openjdk-8-jdk-headless \
    expect

if [[ ! -x "$(command -v docker)" ]]; then
    sudo apt-get install -y docker.io
    # Allow to run Docker without sudo
    sudo chmod u+s $(which docker)
fi
