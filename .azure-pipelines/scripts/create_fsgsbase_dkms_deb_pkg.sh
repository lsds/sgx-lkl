#!/bin/bash

#shellcheck disable=SC2086,SC2154

set -e

# This script creates a Debian package that contains a DKMS-enabled kernel module
# that enables the FSGSBASE bit.
# Note that installation of the package DOES NOT enable the kernel module.
# It must be manually added to /etc/modules with name "enable_fsgsbase".

if [ -z $SGXLKL_ROOT ]; then
    echo "ERROR: 'SGXLKL_ROOT' is undefined. Please export SGXLKL_ROOT=<SGX-LKL-OE> source code repository"
    exit 1
fi

function req() {
    [[ -x "$(command -v $1)" ]] || (echo "The following application/package is required and could not be found: $1."; exit 1)
}

req dkms
req dh # debhelper package, required by `dkms mkdeb`

module_name=enable_fsgsbase
deb_pkg_name=enable-fsgsbase-dkms
module_version=${module_version:-1.0.0}

tmp_dir=$SGXLKL_ROOT/build/deb-fsgsbase-tmp
src_base_dir=$tmp_dir/src
src_dir=$src_base_dir/$module_name-$module_version
build_dir=$tmp_dir/build

rm -rf $tmp_dir
mkdir -p $src_dir $build_dir $pkg_dir

cp $SGXLKL_ROOT/tools/kmod-set-fsgsbase/* $src_dir

cat << EOF > $src_dir/dkms.conf
PACKAGE_NAME="$deb_pkg_name"
PACKAGE_VERSION="$module_version"
BUILT_MODULE_NAME[0]="mod_set_cr4_fsgsbase"
DEST_MODULE_NAME[0]="$module_name"
DEST_MODULE_LOCATION="/kernel/drivers/$module_name"
MODULES_CONF[0]="options $module_name val=1"
AUTOINSTALL="yes"
REMAKE_INITRD="no"
EOF

dkms_args="--dkmstree $build_dir --sourcetree $src_base_dir"

set -x
dkms add $dkms_args -m $module_name -v $module_version

# `build` is not necessary for creating the Debian package, but
# we want to make sure the installed module can actually be built,
# at least on the host kernel.
# Note: Any error messages regarding failed signing can be ignored.
dkms build $dkms_args -m $module_name -v $module_version

dkms mkdeb $dkms_args -m $module_name -v $module_version --source-only
set +x

deb_filename=${deb_pkg_name}_${module_version}_amd64.deb
cp $build_dir/$module_name/$module_version/deb/$deb_filename $SGXLKL_DEB_DIR

echo "Done! Install with: sudo apt install $SGXLKL_DEB_DIR/$deb_filename"
