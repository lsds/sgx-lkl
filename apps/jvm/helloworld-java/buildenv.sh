#!/bin/sh

set -ex

apk update
apk add iputils iproute2 unzip libstdc++ openjdk8-jre nss
