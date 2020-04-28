#!/bin/bash

set -e

if [ -z $SGXLKL_ROOT ]; then
    echo "ERROR: 'SGXLKL_ROOT' is undefined. Please export SGXLKL_ROOT=<SGX-LKL-OE> source code repository"
    exit 1
fi

function req() {
    [[ -x "$(command -v $1)" ]] || (echo "The following application/package is required and could not be found: $1."; exit 1)
}

req apt-ftparchive

repo_dir=$SGXLKL_ROOT/build/deb-apt-repo

rm -rf $repo_dir
mkdir $repo_dir
cd $repo_dir

deb_dir=.
mkdir -p $deb_dir

cp $SGXLKL_ROOT/build/deb/pkg/* $deb_dir

# Optional.
if [[ -d $SGXLKL_ROOT/build/deb-fsgsbase ]]; then
    cp $SGXLKL_ROOT/build/deb-fsgsbase/pkg/* $deb_dir
fi

apt-ftparchive packages $deb_dir > Packages
apt-ftparchive release . > Release

pwd
ls -alh .
ls -alh $deb_dir
