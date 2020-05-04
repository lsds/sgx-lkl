#!/bin/bash

set -ex

mkdir -p ~/.ssh > /dev/null
chmod 700 ~/.ssh
ssh-keyscan -t rsa github.com >> ~/.ssh/known_hosts
find .git -type f -name '*.lock' -exec rm -v {} +
git reset --hard
git submodule sync
git submodule update --init --force --recursive --depth 1
git submodule foreach git reset --hard
git clean -xdf
git submodule foreach git clean -xdf
