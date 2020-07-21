#! /bin/bash

# In this scenario we have two enclaves: sgxlkl enclave and oe enclave. 
# oe_enclave is the tls server and runs and waits for connection from sgxlkl_enclave.
# then sgxlkl_enclave starts and connects to oe_enclave by using pre-created sgxlkl_cert.der and sgxlkl_private_key.pem
# then both sides will shows the result

# Verify that dependent env variables are available
if [[ -z $SGXLKL_ROOT || -z $SGXLKL_RUN_MODE ]]; then
    echo "Dependent environment variables for this scenario not available."
    exit 1
fi

# Install Open Enclave if not installed
if [[ ! -d "/opt/openenclave" ]]; then
    # Configure the Intel and Microsoft APT Repositories
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
    wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -

    echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-7 main" | sudo tee /etc/apt/sources.list.d/llvm-toolchain-bionic-7.list
    wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -

    echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | sudo tee /etc/apt/sources.list.d/msprod.list
    wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

    # Install the Intel and Open Enclave packages and dependencies
    sudo apt -y install clang-7 libssl-dev gdb libsgx-enclave-common libsgx-enclave-common-dev libprotobuf10 libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client open-enclave
fi

# Set log file that will be shared between two enclaves in the test scenario for stdout and stderr logs
export ATTESTED_TLS_TEST_LOG_FILE=$SGXLKL_ROOT/attested_tls_test.log
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

# Build and run OE enclave app
cd oe_enclave || exit 1
make
make run

# Build and run SGX-LKL enclave app
cd ..
cd sgxlkl_enclave || exit 1
make lkl-image
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
