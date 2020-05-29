#!/bin/bash

if [ -z $SGXLKL_ROOT ]; then
    echo "ERROR: 'SGXLKL_ROOT' is undefined. Please export SGXLKL_ROOT=<SGX-LKL-OE> source code repository"
    exit 1
fi

if [ ! -f "Makefile" ]; then
    echo "ERROR: ${0} can only be invoked from a directory that contains Makefile"
    exit 1
fi

# Get the timeout from the test module
DEFAULT_TIMEOUT=300
timeout=$(make gettimeout 2> /dev/null)
[[ $? -ne 0 ]] && timeout=$DEFAULT_TIMEOUT
echo "Execution timeout: $timeout"

timeout --kill-after=$(($timeout + 15))  $timeout make run-hw
timeout --kill-after=$(($timeout + 15))  $timeout make run-sw

if ls *.img 1> /dev/null 2>&1; then
    mkdir img
    sudo umount img
    sudo mount -o loop *.img img
    sudo rm -rf $SGXLKL_ROOT/cov
    mkdir $SGXLKL_ROOT/cov
    
    # Gather all necessary files for lcov
    cp -r $SGXLKL_ROOT/src/* $SGXLKL_ROOT/cov
    sudo cp -r img$SGXLKL_ROOT/build_musl $SGXLKL_ROOT/cov
    sudo cp -r img$SGXLKL_ROOT/sgx-lkl-musl $SGXLKL_ROOT/cov
    sudo cp -r $SGXLKL_ROOT/build_musl $SGXLKL_ROOT/cov
    sudo cp -r $SGXLKL_ROOT/sgx-lkl-musl $SGXLKL_ROOT/cov
    
    echo "Creating $SGXLKL_ROOT/cov.info"
    sudo lcov -d $SGXLKL_ROOT/cov -c -o $SGXLKL_ROOT/cov.info

    # Accumulate the coverage data with data from other tests
    if [ ! -f "$SGXLKL_ROOT/total_cov.info" ]; then
       echo "Copy the code coverage for the 1st run"
       sudo mv $SGXLKL_ROOT/cov.info $SGXLKL_ROOT/total_cov.info
    else
       echo "Aggregating code coverage to $SGXLKL_ROOT/total_cov.info..."
       sudo lcov -a $SGXLKL_ROOT/total_cov.info -a $SGXLKL_ROOT/cov.info -o $SGXLKL_ROOT/total_cov.info
    fi

    # clean up
    echo "Cleaning up..."
    sudo umount img
    rm -rf img
else
    echo "ERROR: disk image is not created"
    exit 1
fi

exit 0