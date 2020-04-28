#!/bin/bash

mkdir -p ~/.ssh > /dev/null
chmod 700 ~/.ssh
ssh-keyscan -t rsa github.com >> ~/.ssh/known_hosts
git reset --hard
git submodule sync
git submodule update --init --force --recursive
git submodule foreach git reset --hard
git clean -f -d
git submodule foreach git clean -f -d