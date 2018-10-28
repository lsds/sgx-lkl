#!/bin/sh

set -ex

PATH=/usr/sbin:/sbin:/usr/bin:/bin

cd /home
apk update
apk add iputils iproute2 unzip libstdc++
apk add redis

