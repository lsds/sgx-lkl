#!/bin/sh

set -ex

apk update
apk add iputils iproute2 unzip libstdc++
