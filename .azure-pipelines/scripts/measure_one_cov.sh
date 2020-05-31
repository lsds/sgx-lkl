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
run_hw_rc=$?
echo "run-hw return code: $run_hw_rc"
timeout --kill-after=$(($timeout + 15))  $timeout make run-sw
run_sw_rc=$?
echo "run-sw return code: $run_sw_rc"

if [[ $run_hw_rc -eq 0 || $run_sw_rc -eq 0 ]]; then
    sudo rm -rf $SGXLKL_ROOT/cov
    mkdir $SGXLKL_ROOT/cov
    cp -r $SGXLKL_ROOT/src/* $SGXLKL_ROOT/cov

    mkdir img
    sudo umount img
    for imgfile in *.img
    do
      sudo mount -o loop $imgfile img
      # Gather all necessary files for lcov from the mounted image
      sudo cp -r img$SGXLKL_ROOT/build_musl $SGXLKL_ROOT/cov
      sudo cp -r img$SGXLKL_ROOT/sgx-lkl-musl $SGXLKL_ROOT/cov
    done

    sudo cp -r $SGXLKL_ROOT/build_musl $SGXLKL_ROOT/cov
    sudo cp -r $SGXLKL_ROOT/sgx-lkl-musl $SGXLKL_ROOT/cov

    echo "Creating $SGXLKL_ROOT/cov.info"
    sudo lcov -d $SGXLKL_ROOT/cov -c -o $SGXLKL_ROOT/cov.info

    # Accumulate the coverage data with data from other tests
    if [ ! -f "$SGXLKL_ROOT/total_cov.info" ]; then
       if [ -s "$SGXLKL_ROOT/cov.info" ]; then
          echo "Copy the code coverage for the 1st run"
          sudo mv $SGXLKL_ROOT/cov.info $SGXLKL_ROOT/total_cov.info
       else
          echo "cov.info is empty"
       fi
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