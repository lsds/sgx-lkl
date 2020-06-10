#!/bin/bash

set -e

# This script generates a Debian package where all shared library dependencies
# are bundled with the host executable such that it can be run stand-alone
# without having other packages installed. The main purpose is to be able to
# volume mount an SGX-LKL installation into a Docker container without requiring
# the container to have any runtime dependencies installed.
#
# The folder structure of the installed Debian package is as follows:
#
# /opt/sgx-lkl
#   bin/
#     sgx-lkl-run-oe
#     ...
#   lib/
#     libsgxlkl.so.signed
#     external/
#       ld-linux-x86-64.so.2
#       libdcap_quoteprov.so
#       libcurl.so.4
#       libgcc_s.so.1
#       ...
#   tools/
#
# In general, this reflects a regular SGX-LKL installation tree plus the lib/external
# folder containing all bundled libraries.
#
# Implementation notes:
#
# The package we create is fully bundled, meaning it contains all dependencies
# including glibc and the loader library.
# 
# Automatic dependency discovery relies on dynamically linked libraries, however, some
# libraries like the Azure DCAP Client are dlopen'd at runtime.
# Because of that, there is extra logic that deals with bundling them manually.

if [ -z $SGXLKL_ROOT ]; then
    echo "ERROR: 'SGXLKL_ROOT' is undefined. Please export SGXLKL_ROOT=<SGX-LKL-OE> source code repository"
    exit 1
fi

if [ -z $SGXLKL_PREFIX ]; then
    echo "ERROR: 'SGXLKL_PREFIX' is undefined. Please export SGXLKL_PREFIX=<SGX-LKL-OE> install prefix directory"
    exit 1
fi

if [ -z $SGXLKL_BUILD_MODE ]; then
    echo "ERROR: 'SGXLKL_BUILD_MODE' is undefined. Please export SGXLKL_BUILD_MODE=<debug|nonrelease>"
    exit 1
fi

. $SGXLKL_ROOT/.azure-pipelines/scripts/set_version.sh

if [[ $SGXLKL_BUILD_MODE == release ]]; then
    suffix=
else
    suffix="-$SGXLKL_BUILD_MODE"
fi

deb_pkg_name=clc$suffix
deb_pkg_license=/usr/share/common-licenses/GPL-2
install_prefix=/opt/sgx-lkl$suffix
external_lib_dir=lib/external
exe_name=sgx-lkl-run-oe
exe_path=$SGXLKL_PREFIX/bin/$exe_name

deb_pkg_version=${SGXLKL_VERSION}
deb_pkg_full_name=${deb_pkg_name}_${deb_pkg_version}

tmp_dir=$SGXLKL_ROOT/build/deb
pkg_dir=$tmp_dir/pkg
deb_root_dir=$tmp_dir/$deb_pkg_full_name
deb_install_prefix=$deb_root_dir$install_prefix

rm -rf $tmp_dir
mkdir -p $tmp_dir

mkdir -p $deb_install_prefix

# Copy installation prefix into Debian package tree.
cp -r $SGXLKL_PREFIX/. $deb_install_prefix

# Bundle all dependencies.
SGXLKL_PREFIX=$deb_install_prefix SGXLKL_TARGET_PREFIX=$install_prefix \
    $SGXLKL_ROOT/tools/make_self_contained.sh

# Build the .deb package.
mkdir $deb_root_dir/DEBIAN
cat << EOF > $deb_root_dir/DEBIAN/control
Package: ${deb_pkg_name}
Version: ${deb_pkg_version}
Priority: optional
Architecture: amd64
Maintainer: Microsoft <help@microsoft.com>
Description: Confidential Linux Containers standalone distribution for Linux
EOF

# Assemble license files of all bundled libraries.
pkgs=()
for lib_path in $deb_install_prefix/$external_lib_dir/*; do
    lib_name=${lib_path##*/}
    pkg=$(dpkg -S \*/$lib_name | grep -v -e clc -e i386 | head -1 | cut -f1 -d":")
    if [[ -z $pkg ]]; then
        echo "No package found that contains $lib_name! Exiting..."
        exit 1
    fi
    pkgs+=( $pkg )
done
uniq_pkgs=($(printf "%s\n" "${pkgs[@]}" | sort -u | tr '\n' ' '))
NL=$'\n'
copyright="$(cat $deb_pkg_license)"
copyright="$copyright$NL$NL==================${NL}THIRD-PARTY NOTICES"
for pkg in "${uniq_pkgs[@]}"; do
    copyright_path=/usr/share/doc/$pkg/copyright
    if [ ! -f $copyright_path ]; then
        echo "No copyright file found for $pkg! Exiting..."
        exit 1
    fi
    copyright="$copyright$NL$NL##################$NL$(cat $copyright_path)"
done
echo "$copyright" > $deb_root_dir/DEBIAN/copyright

cd $tmp_dir
dpkg-deb --build $deb_pkg_full_name
mkdir -p $pkg_dir
mv $deb_pkg_full_name.deb $pkg_dir

echo "Done! Install with: sudo apt install $pkg_dir/$deb_pkg_full_name.deb"
