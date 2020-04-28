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
#       libcurl-f3c19fde.so.4.5.0
#       libgcc_s-e78f03a3.so.1
#       ...
#   tools/
#
# In general, this reflects a regular SGX-LKL installation tree plus the lib/external
# folder containing all bundled libraries.
#
# Implementation notes:
#
# This script relies on the auditwheel tool from the Python packaging ecosystem.
# It is normally used to discover and bundle all dynamically linked dependencies of native
# extension modules of a Python package such that it can be distributed in binary form on the
# Python package index. This is done by constructing a hierarchical tree of
# dependencies, copying those dependencies into a common folder, and patching the
# rpaths. Here, we simply pretend to be a Python package and make use of the same
# machinery. There is a similar tool for macOS called "delocate" which works not
# just on Python packages but also plain folders, but auditwheel does not have this
# option, which is why we need to put our files into a dummy Python package and extract
# them from the resulting package file again.
#
# auditwheel copies all libraries into a <pkgname>.libs folder, however,
# because we want the files to live in lib/external we do minimal additional
# rpath patching using the patchelf tool (which auditwheel also relies upon).
#
# The package we create is fully bundled, meaning it contains all dependencies
# including glibc and the loader library. This is different from what auditwheel
# normally does as it assumes Python will run on a Linux distribution that can run
# binaries produced by an old CentOS system. This old CentOS system is described by
# a policy: https://github.com/pypa/auditwheel/blob/master/auditwheel/policy/policy.json.
# In our case, we don't make any assumptions and produce a self-contained package
# that can run on any Linux distribution. For that, we use our own policy file
# and also take an additional step to bundle the dynamic loader library (also 
# called the interpreter, or PT_INTERP) since auditwheel does not touch that and it is
# different from regular dependencies.
# 
# Automatic dependency discovery relies on dynamically linked libraries, however, the
# Azure DCAP Client library is dlopen'd by one of the Intel SGX libraries at runtime.
# Because of that, there is extra logic that deals with bundling of this library.

if [ -z $SGXLKL_ROOT ]; then
    echo "ERROR: 'SGXLKL_ROOT' is undefined. Please export SGXLKL_ROOT=<SGX-LKL-OE> source code repository"
    exit 1
fi

if [ -z $SGXLKL_PREFIX ]; then
    echo "ERROR: 'SGXLKL_PREFIX' is undefined. Please export SGXLKL_PREFIX=<SGX-LKL-OE> install prefix directory"
    exit 1
fi

. $SGXLKL_ROOT/.azure-pipelines/scripts/set_version.sh

auditwheel_version=3.1.0
patchelf_version=0.10

deb_pkg_name=clc
install_prefix=/opt/sgx-lkl
exe_name=sgx-lkl-run-oe

# Special treatment, not dynamically linked.
az_dcap_client_lib_name=libdcap_quoteprov.so
az_dcap_client_lib_path=/usr/lib/$az_dcap_client_lib_name

# Special treatment, not dynamically linked (required by libcurl).
libnss_name=libnss_dns.so.2
libnss_path=/lib/x86_64-linux-gnu/$libnss_name

# Special treatment, enclave images used by libsgx libraries.
libsgx_enclave_image_dir=/usr/lib/x86_64-linux-gnu
libsgx_enclave_image_paths=(
    $libsgx_enclave_image_dir/libsgx_pce.signed.so
    $libsgx_enclave_image_dir/libsgx_qe3.signed.so
    $libsgx_enclave_image_dir/libsgx_qve.signed.so
)

if [ ! -f $az_dcap_client_lib_path ]; then
    echo "Azure DCAP Client library not found: $az_dcap_client_lib_path"
    exit 1
fi

deb_pkg_version=${SGXLKL_VERSION}
deb_pkg_full_name=${deb_pkg_name}_${deb_pkg_version}

tmp_dir=$SGXLKL_ROOT/build/deb
pkg_dir=$tmp_dir/pkg
deb_root_dir=$tmp_dir/$deb_pkg_full_name
deb_install_prefix=$deb_root_dir$install_prefix

rm -rf $tmp_dir
mkdir -p $tmp_dir

# Create Python venv for auditwheel package.
venv_path=$tmp_dir/venv
python3 -m venv $venv_path
. $venv_path/bin/activate

# Install auditwheel from source as we need to patch it.
cd $tmp_dir
git clone https://github.com/pypa/auditwheel || true
cd auditwheel
git checkout $auditwheel_version

# auditwheel policies are hard-coded for manylinux* scenarios. We copy our own.
cat << EOF > auditwheel/policy/policy.json
[
    {"name": "linux",
     "priority": 0,
     "symbol_versions": {},
     "lib_whitelist": []
    }
]
EOF

# Patch auditwheel to avoid renaming bundled libraries.
# Renaming them causes issues with libdl's dlopen.
echo "\
@@ -129,6 +129,7 @@
         new_soname = '%s-%s.%s' % (base, shorthash, ext)
     else:
         new_soname = src_name
+    new_soname = src_name
" | patch -u auditwheel/repair.py

echo "\
@@ -255,6 +255,7 @@
     for ldpath in ldpaths:
         path = os.path.join(ldpath, lib)
         target = readlink(path, root, prefixed=True)
+        target = path
" | patch -u auditwheel/lddtree.py

# Install auditwheel
pip install .

# auditwheel relies on the patchelf tool to patch rpaths.
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

# Use auditwheel to move shared library dependencies next to executable, patching all rpaths.
mkdir $tmp_dir/wheel
cd $tmp_dir/wheel
py_pkg_name=tmp
echo "from setuptools import setup; setup(name='$py_pkg_name', packages=['tmp'], package_data={'tmp': ['*']})" > setup.py
mkdir tmp
cp $SGXLKL_PREFIX/bin/$exe_name tmp/
# Special handling for the Azure DCAP Client library.
# This library is loaded at runtime (dlopen) by the Intel SGX libraries from a
# hard-coded filename (libdcap_quoteprov.so) and is not dynamically linked.
cp $az_dcap_client_lib_path tmp/
# Special handling for libnss which is loaded at runtime (dlopen) by libcurl or
# one of its dependencies.
cp $libnss_path tmp/
python setup.py bdist_wheel
cd $tmp_dir/auditwheel
wheel_filename=$py_pkg_name-*.whl
auditwheel -v repair --no-update-tags \
    --wheel-dir $tmp_dir/wheel/wheelhouse $tmp_dir/wheel/dist/$wheel_filename
cd $tmp_dir/wheel/wheelhouse
unzip $wheel_filename

# Copy into final Debian package location and adjust root rpath.
mkdir -p $deb_install_prefix
cp -r $SGXLKL_PREFIX/. $deb_install_prefix
mkdir -p $deb_install_prefix/lib/external
cp tmp/$exe_name $deb_install_prefix/bin
cp tmp/$az_dcap_client_lib_name $deb_install_prefix/lib/external
cp tmp/$libnss_name $deb_install_prefix/lib/external
cp -r $py_pkg_name.libs/. $deb_install_prefix/lib/external
patchelf --force-rpath --set-rpath "\$ORIGIN/../lib/external" $deb_install_prefix/bin/$exe_name
# auditwheel does not add rpaths for dependencies.
# This would work out normally as libraries are renamed to have unique names with hashes.
# We disabled this however (see beginning of file) so we need to add
# an explicit rpath to avoid that libraries from other search locations are used.
for lib_path in $deb_install_prefix/lib/external/*; do
    patchelf --force-rpath --set-rpath "\$ORIGIN" $lib_path
done
# Copy enclave images needed by libsgx libraries.
for path in ${libsgx_enclave_image_paths[@]}; do
    cp $path $deb_install_prefix/lib/external
done

# auditwheel does not touch the interpreter path, let's bundle it ourselves.
# Note that the interpreter has to be a valid absolute path as this is read
# directly by the kernel which does not use the rpath etc for resolution.
interp_path=$(patchelf --print-interpreter $deb_install_prefix/bin/$exe_name)
interp_filename=$(basename $interp_path)
cp $interp_path $deb_install_prefix/lib/external
interp_install_path=$install_prefix/lib/external/$interp_filename
patchelf --set-interpreter $interp_install_path $deb_install_prefix/bin/$exe_name

# Sanity check 1: ldd will fail if patchelf broke something badly,
# though note that this does not check whether libraries can be resolved.
set -x
ldd $deb_install_prefix/bin/$exe_name
ldd $deb_install_prefix/lib/external/$az_dcap_client_lib_name

patchelf --print-interpreter $deb_install_prefix/bin/$exe_name
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

cd $tmp_dir
dpkg-deb --build $deb_pkg_full_name
mkdir -p $pkg_dir
mv $deb_pkg_full_name.deb $pkg_dir

echo "Done! Install with: sudo apt install $pkg_dir/$deb_pkg_full_name.deb"
