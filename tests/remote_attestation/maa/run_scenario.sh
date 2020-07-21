#! /bin/bash

# In this scenario we have two enclaves: sgxlkl_enclave and oe_enclave. 
# oe_enclave is the tls server and runs and waits for connection from sgxlkl_enclave.
# sgxlkl_enclave starts and connects to oe_enclave
# sgxlkl_enclave gets the report from oe_enclave and then gets authentication token from AAD
# sgxlkl_enclave calls MAA for JWT token and gets, parses and verifies it 

# Verify that dependent env variables are available
if [[ -z $SGXLKL_ROOT || -z $SGXLKL_RUN_MODE || -z $MAA_CLIENT_ID || -z $MAA_CLIENT_SECRET  || -z $MAA_APP_ID || -z $MAA_ADDR || -z $MAA_ADDR_APP ]]; then
    echo "Dependent environment variables for this scenario not available."
    exit 1
fi

# If openenclave is not installed, install it
if [[ ! -d "/opt/openenclave" ]]; then
    home=$(pwd)
    cd ~
    sudo rm -rf openenclave/
    openenclave_install_dir="/opt/openenclave/"
    git clone --recursive -b feature/sgx-lkl-support https://github.com/openenclave/openenclave.git
    cd openenclave

    sed -i '/add_subdirectory(tests)/d' CMakeLists.txt

    sudo bash scripts/ansible/install-ansible.sh
    sudo ansible-playbook scripts/ansible/oe-contributors-acc-setup-no-driver.yml

    mkdir -p build
    cd build
    cmake -G "Ninja"  -DWITH_EEID=1 ..
    sudo ninja
    sudo ninja install
    if [[ $? -eq 0 ]]; then
        echo "OE SDK installed successfully"
    else
        echo "OE SDK install failed"
        exit 1
    fi
    cd $home
fi

# Set log file that will be shared between two enclaves in the test scenario for stdout and stderr logs
# In sgx-lkl test framework can have one log file for stdout and stderr. This log file is called with cat to be included in test's output
# This file is also searched for some key sentences to verify TLS connection and MAA attestation results
export MAA_TEST1_LOG_FILE=$SGXLKL_ROOT/remote_attestation_maa_test.log
date > $MAA_TEST1_LOG_FILE

# Kill hanging processes if exist
process="sgx-lkl-run-oe"
if pgrep -x $process >/dev/null; then
    echo "SGX-LKL is still running:"
    # shellcheck disable=SC2009
    ps -aux | grep $process
    echo "Trying to kill hanging $process process"
    sudo pkill -9 $process
    # pkill does not block.
    sleep 5
fi

process="oeApp_host"
if pgrep -x $process >/dev/null; then
    echo "OE Enclave is still running:"
    # shellcheck disable=SC2009
    ps -aux | grep $process
    echo "Trying to kill hanging $process process"
    sudo pkill -9 $process
    # pkill does not block.
    sleep 5
fi

# Build and run OE enclave app
cd oe_enclave
make
make run

# Build and run SGX-LKL enclave app
cd ..
cd sgxlkl_enclave
make lkl-image
make lkl-run

# Check the log file and decide if test passed
maa_token=$(grep 'MAA JWT token obtained' $MAA_TEST1_LOG_FILE | wc -l)
maa_parsed=$(grep 'Successfully parsed MAA JWT token' $MAA_TEST1_LOG_FILE | wc -l)
maa_token_product_id=$(grep 'Successfully extracted product id from MAA JWT' $MAA_TEST1_LOG_FILE | wc -l)
maa_token_oe_id=$(grep 'Successfuly populated OE identity from MAA JWT' $MAA_TEST1_LOG_FILE | wc -l)
oe_identity_verified=$(grep 'OE identify verified successfully' $MAA_TEST1_LOG_FILE | wc -l)

cat $MAA_TEST1_LOG_FILE
[[ $maa_token -eq 1 && $maa_parsed -eq 1 && $maa_token_product_id -eq 1 && $maa_token_oe_id -eq 1 && $oe_identity_verified -eq 1 ]] && echo "TEST PASSED" && exit 0
echo "TEST FAILED"
exit 1
