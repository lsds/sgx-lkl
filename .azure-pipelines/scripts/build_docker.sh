#!/bin/bash

if [ -z $SGXLKL_ROOT ]; then
    echo "ERROR: 'SGXLKL_ROOT' is undefined. Please export SGXLKL_ROOT=<SGX-LKL-OE> source code repository"
    exit 1
fi

if [[ "$is_debug" == "false" ]]; then
    echo "ERROR: is_debug=false currently not supported"
    exit 1
fi

. /opt/openenclave/share/openenclave/openenclaverc
. $SGXLKL_ROOT/.azure-pipelines/scripts/junit_utils.sh

# Initialize the variables.
test_name="Compile and build via Docker"
test_class="BVT"
test_suite="sgx-lkl-oe"
error_message_file_path="report/$test_name.error"
stack_trace_file_path="report/$test_name.stack"

# Start the test timer.
JunitTestStarted "$test_name"

# Run the test.

# Ensure we have a pristine environment
git submodule foreach --recursive git clean -xdf

$SGXLKL_ROOT/tools/sgx-lkl-docker build-sgxlkl
exit_code=$?
if [[ $exit_code == 0 ]] && [[ "$SGXLKL_PREFIX" != "" ]]; then
    make install PREFIX=$SGXLKL_PREFIX
    exit_code=$?
fi

# Process the result
if [[ $exit_code == 0 ]] && [ -f build/sgx-lkl-run-oe ] && [ -f build/libsgxlkl.so.signed ] && [ -f build/libsgxlkl.so ]; then
    JunitTestFinished "$test_name" "passed" "$test_class" "$test_suite"
else
    echo "'$test_name' exited with $exit_code" > "$error_message_file_path"
    JunitTestFinished "$test_name" "failed" "$test_class" "$test_suite"
fi
exit $exit_code
