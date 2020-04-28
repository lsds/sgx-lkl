#!/bin/sh

set -ex

PATH=/usr/sbin:/sbin:/usr/bin:/bin

apk update
apk add iputils iproute2
apk add device-mapper cryptsetup
