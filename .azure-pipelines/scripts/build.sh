#!/bin/bash

if [ -z $SGXLKL_ROOT ]; then
    echo "ERROR: 'SGXLKL_ROOT' is undefined. Please export SGXLKL_ROOT=<SGX-LKL-OE> source code repository"
    exit 1
fi

. /opt/openenclave/share/openenclave/openenclaverc
. $SGXLKL_ROOT/.azure-pipelines/scripts/junit_utils.sh

# Initialize the variables.
if [[ "$build_mode" == "debug" ]]; then
    make_args="DEBUG=true"
elif [[ "$build_mode" == "nondebug" ]]; then
    make_args="DEBUG=false"
else
    echo "unknown build_mode: $build_mode"
    exit 1
fi
test_name="Compile and build ($build_mode)"
test_class="BVT"
test_suite="sgx-lkl-oe"
error_message_file_path="report/$test_name.error"
stack_trace_file_path="report/$test_name.stack"

# Start the test timer.
JunitTestStarted "$test_name"

# Ensure we have a pristine environment
git submodule foreach --recursive git clean -xdf
make clean
make $make_args
make_exit=$?

# Set up host networking and FSGSBASE userspace support
$SGXLKL_ROOT/tools/sgx-lkl-setup
setup_exit=$?

# Process the result
if [[ "$make_exit" == "0" ]] && [[ "$setup_exit" == "0" ]] && [[ -f build/sgx-lkl-run-oe ]] && [[ -f build/libsgxlkl.so.signed ]] && [[ -f build/libsgxlkl.so ]]; then
    JunitTestFinished "$test_name" "passed" "$test_class" "$test_suite"
else
    echo "'$test_name' exited with $make_exit" > "$error_message_file_path"
    make DEBUG=true > "$stack_trace_file_path"  2>&1
    $SGXLKL_ROOT/tools/sgx-lkl-setup >> "$stack_trace_file_path"  2>&1
    JunitTestFinished "$test_name" "failed" "$test_class" "$test_suite"
fi

if [[ "$make_exit" == "0" ]]; then
    exit $setup_exit
else
    exit $make_exit
fi
