#!/bin/bash
# This script will be further enhanced to include more miniroot tests.
. .azure-pipelines/scripts/junit_utils.sh

# Initialize the variables.
test_name="Execute whoami using miniroot in --hw-debug and --sw-debug modes"
test_class="BVT"
test_suite="sgx-lkl-oe"
error_message_file_path="report/$test_name.error"
stack_trace_file_path="report/$test_name.stack"

# Start the test timer.
JunitTestStarted "$test_name"

sgx_lkl_run_oe_path="./build/sgx-lkl-run-oe"

if [ -f "$sgx_lkl_run_oe_path" ]; then 
    $sgx_lkl_run_oe_path --version
    exit_code=$?
else
    echo "Error: Unable to find $sgx_lkl_run_oe_path."
    exit 1
fi

# Build the miniroot
cd samples/miniroot
make
cd ../../

# Test 1 : whoami
sw_debug_whoami=$(./build/sgx-lkl-run-oe --sw-debug samples/miniroot/sgxlkl-miniroot-fs.img /usr/bin/whoami)
echo "Command: ./build/sgx-lkl-run-oe --sw-debug samples/miniroot/sgxlkl-miniroot-fs.img /usr/bin/whoami"
echo "Output: $sw_debug_whoami"

hw_debug_whoami=$(./build/sgx-lkl-run-oe --hw-debug samples/miniroot/sgxlkl-miniroot-fs.img /usr/bin/whoami)
echo "Command: ./build/sgx-lkl-run-oe --hw-debug samples/miniroot/sgxlkl-miniroot-fs.img /usr/bin/whoami"
echo "Output: $hw_debug_whoami"

if [[ "$sw_debug_whoami" != "root" ]]; then
    echo "Error: sw_debug_whoami = $sw_debug_whoami. (Expected 'root')"
    exit_code=1
fi
if [[ "$hw_debug_whoami" != "root" ]]; then
    echo "Error: hw_debug_whoami = $hw_debug_whoami. (Expected 'root')"
    exit_code=1
fi

# Process the result
if [[ "$exit_code" == 0 ]]; then
    JunitTestFinished "$test_name" "passed" "$test_class" "$test_suite"
else
    echo "'$test_name' exited with $exit_code" > "$error_message_file_path"
    ./build/sgx-lkl-run-oe --sw-debug samples/miniroot/sgxlkl-miniroot-fs.img /usr/bin/whoami > "$stack_trace_file_path" 2>&1
    ./build/sgx-lkl-run-oe --hw-debug samples/miniroot/sgxlkl-miniroot-fs.img /usr/bin/whoami >> "$stack_trace_file_path" 2>&1
    JunitTestFinished "$test_name" "failed" "$test_class" "$test_suite"
fi

# Cleanup 
echo "Cleanup ..."
cd samples/miniroot
make clean

# Exit with 0 to allow run further tests.
exit 0