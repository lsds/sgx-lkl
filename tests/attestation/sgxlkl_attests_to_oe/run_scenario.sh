#! /bin/bash

# In this scenario, we have two enclaves: sgxlkl enclave and oe enclave. 
# oe_enclave is the tls server and runs and waits for connection from sgxlkl_enclave.
# then sgxlkl_enclave starts and connects to oe_enclave by using pre-created sgxlkl_cert.der and sgxlkl_private_key.pem
# then both sides will shows the result

# Run mode is sw or hw
export SGXLKL_RUN_MODE=$1

# Verify that dependent env variables are available
if [[ -z $SGXLKL_PREFIX || -z $SGXLKL_ROOT || -z $SGXLKL_RUN_MODE ]]; then
    echo "Dependent environment variables for this scenario not available."
    exit 1
fi

# Install Open Enclave if not installed
if [[ ! -d "/opt/openenclave" ]]; then
    home=$(pwd)
    cd ~ || exit 1
    sudo rm -rf openenclave/
    git clone --recursive -b feature/sgx-lkl-support https://github.com/openenclave/openenclave.git
    cd openenclave || exit 1

    sed -i '/add_subdirectory(tests)/d' CMakeLists.txt

    sudo bash scripts/ansible/install-ansible.sh
    sudo ansible-playbook scripts/ansible/oe-contributors-acc-setup-no-driver.yml

    mkdir -p build
    cd build || exit 1
    cmake -G "Ninja"  -DWITH_EEID=1 ..
    sudo ninja
    sudo ninja install
    exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        echo "OE SDK installed successfully"
    else
        echo "OE SDK install failed"
        exit 1
    fi
    cd "$home" || exit 1
fi

# shellcheck disable=SC1091
. /opt/openenclave/share/openenclave/openenclaverc

# Set log file that will be shared between two enclaves in the test scenario for stdout and stderr logs
export ATTESTED_TLS_TEST_LOG_FILE=$SGXLKL_ROOT/report/sgxlkl_attests_to_oe.log
date > "$ATTESTED_TLS_TEST_LOG_FILE"

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

process="tlssrv_host"
if pgrep -x $process >/dev/null; then
    echo "OE Enclave is still running:"
    # shellcheck disable=SC2009
    ps -aux | grep $process
    echo "Trying to kill hanging $process process"
    sudo pkill -9 $process
    # pkill does not block.
    sleep 5
fi

export PATH=$PATH:/opt/openenclave/bin

# Build and run OE enclave app
cd oe_enclave || exit 1
make
exit_code=$?
if [[ $exit_code -ne 0 ]]; then
    echo "Failed to build OE_ENCLAVE"
    exit 1
fi
make run

# Build and run SGX-LKL enclave app
cd ..
cd sgxlkl_enclave || exit 1
make lkl-image
exit_code=$?
if [[ $exit_code -ne 0 ]]; then
    echo "Failed to build SGXLKL_ENCLAVE"
    exit 1
fi
make lkl-run

# Check the log file and decide if test passed
client_success=$(grep -c 'Remote connection established. Ready for service.' "$ATTESTED_TLS_TEST_LOG_FILE")
server_success=$(grep -c 'Server: attestation certificate verified.' "$ATTESTED_TLS_TEST_LOG_FILE")

cat "$ATTESTED_TLS_TEST_LOG_FILE"
if [[ $client_success -eq 1 && $server_success -eq 1 ]]; then
    echo "TEST PASSED"
    exit 0
fi
echo "TEST FAILED"
exit 1
