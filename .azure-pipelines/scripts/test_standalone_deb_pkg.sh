#!/bin/bash

set -e

if [ -z $SGXLKL_ROOT ]; then
    echo "ERROR: 'SGXLKL_ROOT' is undefined. Please export SGXLKL_ROOT=<SGX-LKL-OE> source code repository"
    exit 1
fi

exe_name=sgx-lkl-run-oe
install_prefix=/opt/sgx-lkl # inside deb pkg

deb_dir=$SGXLKL_ROOT/build/deb/pkg
tmp_dir=$SGXLKL_ROOT/build/deb-test

rm -rf $tmp_dir
mkdir -p $tmp_dir

cd $tmp_dir

# Extract deb pkg to simulate host installation
deb_pkg=($deb_dir/*.deb)
deb_pkg=${deb_pkg[0]}
echo "Using $deb_pkg"
dpkg-deb -x $deb_pkg $tmp_dir

# Test 1: Python hello world
echo "Building Python hello world test disk image"
test_dir=$SGXLKL_ROOT/tests/languages/python
test_img=sgxlkl-python.img
img_path=$test_dir/$test_img
cc_name=my-app-cc

make -C $test_dir $test_img
$SGXLKL_ROOT/tools/sgx-lkl-cfg create --disk=$img_path --host-cfg=host-cfg.json --app-cfg=app-cfg.json

# Patch app config:
# 1. Dockerfile has 'python3' as entrypoint, but SGX-LKL needs absolute paths, patch 'run'
# 2. Dockerfile does not contain Python script to run, patch 'args'
python3 -c "\
import json; \
c = json.load(open('app-cfg.json')); \
c['run'] = '/usr/bin/python3'; \
c['args'] = ['/app/python-helloworld.py']; \
json.dump(c, open('app-cfg.json', 'w'), indent=2) \
"

$SGXLKL_ROOT/tools/sgx-lkl-docker build-cc --name=$cc_name --host-cfg=host-cfg.json --app-cfg=app-cfg.json

echo "Running Python hello world test in empty Docker container"
set -x
sudo docker run --rm --privileged \
    -e SGXLKL_VERBOSE=1 -e SGXLKL_KERNEL_VERBOSE=1 \
    -v $tmp_dir/opt:/opt \
    $cc_name \
    --hw-debug

echo "Tests succeeded."
