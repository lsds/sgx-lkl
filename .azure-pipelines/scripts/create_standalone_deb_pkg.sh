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
    echo "ERROR: 'SGXLKL_BUILD_MODE' is undefined. Please export SGXLKL_BUILD_MODE=<debug|nondebug>"
    exit 1
fi

. $SGXLKL_ROOT/.azure-pipelines/scripts/set_version.sh

patchelf_version=0.10

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

dlopened_libs=(
    /usr/lib/libdcap_quoteprov.so # via Intel DCAP library
    /lib/x86_64-linux-gnu/libnss_dns.so.2 # via libcurl (via Azure DCAP Client library)
)

# Extra files needed by libsgx libraries.
libsgx_enclave_image_paths=(
    /usr/lib/x86_64-linux-gnu/libsgx_pce.signed.so
    /usr/lib/x86_64-linux-gnu/libsgx_qe3.signed.so
    /usr/lib/x86_64-linux-gnu/libsgx_qve.signed.so
)

deb_pkg_version=${SGXLKL_VERSION}
deb_pkg_full_name=${deb_pkg_name}_${deb_pkg_version}

tmp_dir=$SGXLKL_ROOT/build/deb
pkg_dir=$tmp_dir/pkg
deb_root_dir=$tmp_dir/$deb_pkg_full_name
deb_install_prefix=$deb_root_dir$install_prefix

rm -rf $tmp_dir
mkdir -p $tmp_dir

# We build patchelf ourselves as the Ubuntu package is too old and has bugs that affect us.
cd $tmp_dir
git clone https://github.com/NixOS/patchelf.git || true
cd patchelf
git checkout $patchelf_version
./bootstrap.sh
./configure --prefix=$tmp_dir/patchelf/dist
make
make install
export PATH=$tmp_dir/patchelf/dist/bin:$PATH

mkdir -p $deb_install_prefix $deb_install_prefix/$external_lib_dir

# Copy installation prefix into Debian package tree.
cp -r $SGXLKL_PREFIX/. $deb_install_prefix

# Copy shared library dependencies into Debian package tree.
# Note that lddtree includes the input executables / libraries as well in its output.
# This is why 'rm' below is removing the (only) executable again.
echo "Shared library dependencies of $exe_path ${dlopened_libs[@]}:"
lddtree -l "$exe_path" "${dlopened_libs[@]}" | sort | uniq
lddtree -l "$exe_path" "${dlopened_libs[@]}" | sort | uniq | xargs -i cp {} $deb_install_prefix/$external_lib_dir
rm $deb_install_prefix/$external_lib_dir/$exe_name

# Patch RPATHs of main executable and shared libraries.
patchelf --force-rpath --set-rpath "\$ORIGIN/../$external_lib_dir" $deb_install_prefix/bin/$exe_name
for lib_path in $deb_install_prefix/lib/external/*; do
    patchelf --force-rpath --set-rpath "\$ORIGIN" $lib_path
done

# Patch the main executable interpreter path.
# Note that the interpreter has to be a valid absolute path as this is read
# directly by the kernel which does not use the rpath etc for resolution.
interp_path=$(patchelf --print-interpreter $deb_install_prefix/bin/$exe_name)
interp_filename=$(basename $interp_path)
cp $interp_path $deb_install_prefix/$external_lib_dir
interp_install_path=$install_prefix/$external_lib_dir/$interp_filename
patchelf --set-interpreter $interp_install_path $deb_install_prefix/bin/$exe_name

# Copy extra data files into Debian package tree.
cp "${libsgx_enclave_image_paths[@]}" $deb_install_prefix/$external_lib_dir

# Sanity check 1: ldd will fail if patchelf broke something badly,
# though note that this does not check whether libraries can be resolved.
set -x
ldd $deb_install_prefix/bin/$exe_name
set +x

# Sanity check 2: Run --help in empty Docker container to check if libs can be resolved.
# Note: This does not check whether the Azure DCAP Client library loads.
tar cv --files-from /dev/null | sudo docker import - empty
sudo docker run --rm -v $deb_install_prefix:$install_prefix empty $install_prefix/bin/$exe_name --help

# Finally, build the .deb package.
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
