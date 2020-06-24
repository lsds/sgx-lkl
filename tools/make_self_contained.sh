#!/bin/bash

set -eo pipefail

# This script transforms an SGX-LKL installation such that all shared library dependencies
# are bundled in the installation prefix and SGX-LKL can be run stand-alone
# without having other packages installed. The main purpose is to be able to
# volume mount an SGX-LKL installation into a Docker container without requiring
# the container to have any runtime dependencies installed.
#
# The folder structure of the self-contained installation is as follows:
#
# /opt/sgx-lkl
#   bin/
#     sgx-lkl-run-oe
#     ...
#   lib/
#     libsgxlkl.so.signed
#     external/
#       ld-linux-x86-64 (symlink to file below)
#       ld-linux-x86-64.so.2
#       libdcap_quoteprov.so
#       libcurl.so.4
#       libgcc_s.so.1
#       ...
#     gdb/
#       ...
#   share/
#     ...
#
# In general, this reflects a regular SGX-LKL installation tree plus the lib/external
# folder containing all bundled libraries.
#
# Implementation notes:
# 
# Automatic dependency discovery relies on dynamically linked libraries, however, some
# libraries like the Azure DCAP Client are dlopen'd at runtime.
# Because of that, there is extra logic that deals with bundling them manually.

if [ -z $SGXLKL_PREFIX ]; then
    echo "ERROR: 'SGXLKL_PREFIX' is undefined. Please export SGXLKL_PREFIX=<SGX-LKL-OE> install prefix directory"
    exit 1
fi

SGXLKL_PREFIX=$(realpath -s $SGXLKL_PREFIX)

# Absolute prefix used for the location of the loader stored in the executable.
# If this does not match at runtime, then the executable must be launched
# with lib/external/ld-linux-x86-64 bin/sgx-lkl-run-oe ...
SGXLKL_TARGET_PREFIX=${SGXLKL_TARGET_PREFIX:-$SGXLKL_PREFIX}

patchelf_version=0.10

external_lib_dir=lib/external
exe_name=sgx-lkl-run-oe
exe_path=$SGXLKL_PREFIX/bin/$exe_name

if [[ ! -f $exe_path ]]; then
    echo "ERROR: $exe_path not found. Is this an installation?"
    exit 1
fi

oegdb_ptrace_lib_name=liboe_ptrace.so
oegdb_ptrace_lib_path=${SGXLKL_PREFIX}/lib/gdb/openenclave/${oegdb_ptrace_lib_name}
dlopened_libs=(
    /usr/lib/libdcap_quoteprov.so # via Intel DCAP library
    /lib/x86_64-linux-gnu/libnss_dns.so.2 # via libcurl (via Azure DCAP Client library)
    ${oegdb_ptrace_lib_path} # via sgx-lkl-gdb
)

# Extra files needed by libsgx libraries.
libsgx_enclave_image_paths=(
    /usr/lib/x86_64-linux-gnu/libsgx_pce.signed.so
    /usr/lib/x86_64-linux-gnu/libsgx_qe3.signed.so
    /usr/lib/x86_64-linux-gnu/libsgx_qve.signed.so
)

# We build patchelf ourselves as the Ubuntu package is too old and has bugs that affect us.
patchelf_dir=/tmp/sgx-lkl-patchelf-$patchelf_version
if [[ ! -d $patchelf_dir ]]; then
    echo "Downloading and building patchelf $patchelf_version"
    mkdir -p $patchelf_dir
    pushd $patchelf_dir
    git clone https://github.com/NixOS/patchelf.git
    pushd patchelf
    git checkout $patchelf_version
    ./bootstrap.sh
    ./configure --prefix=$patchelf_dir/dist
    make
    make install
    popd
    popd
fi
export PATH=$patchelf_dir/dist/bin:$PATH

rpath=$(patchelf --print-rpath $exe_path)
if [[ "$rpath" != "" ]]; then
    echo "Installation is already self-contained."
    exit 1
fi

mkdir -p $SGXLKL_PREFIX/$external_lib_dir

# Copy shared library dependencies into Debian package tree.
# Note that lddtree includes the input executables / libraries as well in its output.
# This is why 'rm' below is removing the (only) executable again.
echo "Shared library dependencies of $exe_path ${dlopened_libs[@]}:"
lddtree -l "$exe_path" "${dlopened_libs[@]}" | sort | uniq
lddtree -l "$exe_path" "${dlopened_libs[@]}" | sort | uniq | xargs -i cp {} $SGXLKL_PREFIX/$external_lib_dir
rm $SGXLKL_PREFIX/$external_lib_dir/$exe_name
rm $SGXLKL_PREFIX/$external_lib_dir/$oegdb_ptrace_lib_name

# Patch RPATHs of main executable and shared libraries.
patchelf --force-rpath --set-rpath "\$ORIGIN/../$external_lib_dir" $SGXLKL_PREFIX/bin/$exe_name
patchelf --force-rpath --set-rpath "\$ORIGIN/../../../$external_lib_dir" $oegdb_ptrace_lib_path
for lib_path in $SGXLKL_PREFIX/lib/external/*; do
    patchelf --force-rpath --set-rpath "\$ORIGIN" $lib_path
done

# Patch the main executable interpreter path.
# Note that the interpreter has to be a valid absolute path as this is read
# directly by the kernel which does not use the rpath etc for resolution.
interp_path=$(patchelf --print-interpreter $SGXLKL_PREFIX/bin/$exe_name)
interp_filename=$(basename $interp_path)
cp $interp_path $SGXLKL_PREFIX/$external_lib_dir
interp_install_path=$SGXLKL_TARGET_PREFIX/$external_lib_dir/$interp_filename
patchelf --set-interpreter $interp_install_path $SGXLKL_PREFIX/bin/$exe_name

# Add a well-known symlink to the loader so that it can be used if needed.
ln -sf $interp_filename $SGXLKL_PREFIX/$external_lib_dir/ld-linux-x86-64

# Copy extra data files into Debian package tree.
cp "${libsgx_enclave_image_paths[@]}" $SGXLKL_PREFIX/$external_lib_dir

# Sanity check 1: ldd will fail if patchelf broke something badly,
# though note that this does not check whether libraries can be resolved.
echo "Running ldd test"
ldd $SGXLKL_PREFIX/bin/$exe_name

# Sanity check 2: Run --help in empty Docker container to check if libs can be resolved.
# Note: This does not check whether the Azure DCAP Client library loads.
tar cv --files-from /dev/null | sudo docker import - empty
echo "Running Docker test 1"
sudo docker run --rm -v $SGXLKL_PREFIX:$SGXLKL_TARGET_PREFIX empty $SGXLKL_TARGET_PREFIX/bin/$exe_name --help
echo "Running Docker test 2"
sudo docker run --rm -v $SGXLKL_PREFIX:/foo empty /foo/lib/external/ld-linux-x86-64 /foo/bin/$exe_name --help

echo "Successfully made installation self-contained."
