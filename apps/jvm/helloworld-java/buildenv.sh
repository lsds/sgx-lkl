#!/bin/sh

set -ex

echo "http://dl-cdn.alpinelinux.org/alpine/v3.6/community" >> /etc/apk/repositories
apk update
apk add iputils iproute2 unzip libstdc++
