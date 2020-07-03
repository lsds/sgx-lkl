#!/bin/bash

if [ -z "$SGXLKL_ROOT" ]; then
    echo "ERROR: 'SGXLKL_ROOT' is undefined. Please export SGXLKL_ROOT=<SGX-LKL-OE> source code repository"
    exit 1
fi
if [ -z "$SGXLKL_PREFIX" ]; then
    echo "ERROR: 'SGXLKL_PREFIX' is undefined. Please export SGXLKL_PREFIX=<install-prefix>"
    exit 1
fi
if [ -z "$SGXLKL_BUILD_MODE" ]; then
    echo "ERROR: 'SGXLKL_BUILD_MODE' is undefined. Please export SGXLKL_BUILD_MODE=<mode>"
    exit 1
fi

# shellcheck source=.azure-pipelines/scripts/junit_utils.sh
. "$SGXLKL_ROOT/.azure-pipelines/scripts/junit_utils.sh"

# Initialize the variables.
if [[ "$SGXLKL_BUILD_MODE" == "debug" ]]; then
    make_args=( "DEBUG=true" )
elif [[ "$SGXLKL_BUILD_MODE" == "nonrelease" ]]; then
    make_args=( )
else
    echo "unknown SGXLKL_BUILD_MODE: $SGXLKL_BUILD_MODE"
    exit 1
fi
make_install_args=( "${make_args[@]}" "PREFIX=$SGXLKL_PREFIX" )
test_name="Compile and build ($SGXLKL_BUILD_MODE)"
test_class="Build"
test_suite="sgx-lkl-oe"
error_message_file_path="report/$test_name.error"
stack_trace_file_path="report/$test_name.stack"

# Start the test timer.
JunitTestStarted "$test_name"

# Ensure that we have a clean build tree
make distclean

# Install the Open Enclave build dependencies for Azure
sudo bash "$SGXLKL_ROOT/openenclave/scripts/ansible/install-ansible.sh"
sudo ansible-playbook "$SGXLKL_ROOT/openenclave/scripts/ansible/oe-contributors-acc-setup-no-driver.yml"

# Let's build
make "${make_args[@]}" && make install "${make_install_args[@]}"
make_exit=$?

# Process the result
if [[ "$make_exit" == "0" ]] && [[ -f build/sgx-lkl-run-oe ]] && [[ -f build/libsgxlkl.so.signed ]] && [[ -f build/libsgxlkl.so ]]; then
    JunitTestFinished "$test_name" "passed" "$test_class" "$test_suite"
else
    echo "'$test_name' exited with $make_exit" > "$error_message_file_path"
    make "${make_args[@]}" > "$stack_trace_file_path"  2>&1
    JunitTestFinished "$test_name" "failed" "$test_class" "$test_suite"
fi

exit $make_exit
