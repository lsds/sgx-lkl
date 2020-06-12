#!/bin/bash

set -e

if [[ $SGXLKL_BUILD_MODE == release ]]; then
    suffix=
else
    suffix="-$SGXLKL_BUILD_MODE"
fi

deb_pkg_name=sgx-lkl$suffix
deb_pkg=($SGXLKL_DEB_DIR/${deb_pkg_name}_*.deb)
deb_pkg=${deb_pkg[0]}
echo "Using $deb_pkg"

sudo rm -rf /opt/sgx-lkl*
# Not using apt install here to simplify subsequent removal.
sudo dpkg-deb -x $deb_pkg /
