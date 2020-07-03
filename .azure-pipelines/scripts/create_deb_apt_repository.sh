#!/bin/bash

set -e

if [ -z "$SGXLKL_ROOT" ]; then
    echo "ERROR: 'SGXLKL_ROOT' is undefined. Please export SGXLKL_ROOT=<SGX-LKL-OE> source code repository"
    exit 1
fi

function req() {
    [[ -x "$(command -v "$1")" ]] || (echo "The following application/package is required and could not be found: $1."; exit 1)
}

req apt-ftparchive

rm -rf "$SGXLKL_APT_REPO_DIR"
mkdir -p "$SGXLKL_APT_REPO_DIR"
cd "$SGXLKL_APT_REPO_DIR"

cp "$SGXLKL_DEB_DIR"/* .

apt-ftparchive packages . > Packages
apt-ftparchive release . > Release

pwd
ls -alh .