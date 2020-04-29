#!/bin/bash
set -ex

sudo apt-get update
sudo apt-get install -y \
    build-essential \
    curl wget rsync pv \
    make gcc g++ bc python xutils-dev flex bison autogen libgcrypt20-dev libjson-c-dev \
    autopoint pkgconf autoconf libtool libcurl4-openssl-dev libprotobuf-dev libprotobuf-c-dev protobuf-compiler protobuf-c-compiler libssl-dev \
    ninja-build ansible linux-headers-$(uname -r) \
    docker.io python3-venv unzip dkms debhelper apt-utils openjdk-8-jdk-headless
