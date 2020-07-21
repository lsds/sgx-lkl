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

# Set log file that will be shared between two enclaves in the test scenario for stdout and stderr logs
export ATTESTED_TLS_TEST_LOG_FILE=$SGXLKL_ROOT/attested_tls_test.log
date > $ATTESTED_TLS_TEST_LOG_FILE

# Kill hanging processes if exist
process="sgx-lkl-run-oe"
if pgrep -x $process >/dev/null; then
    echo "SGX-LKL is still running:"
    # shellcheck disable=SC2009
    ps -aux | grep $process
    echo "Trying to kill hanging $process process"
    sudo pkill -9 $process
    # pkill does not block.
    sleep 1
fi

process="client_host"
if pgrep -x $process >/dev/null; then
    echo "OE Enclave is still running:"
    # shellcheck disable=SC2009
    ps -aux | grep $process
    echo "Trying to kill hanging $process process"
    sudo pkill -9 $process
    # pkill does not block.
    sleep 1
fi

#build sgxlkl_enclave
cd sgxlkl_enclave
make lkl-image

# Build and run OE enclave app
cd ..
cd oe_enclave
make
make run

# run SGX-LKL enclave app
cd ..
cd sgxlkl_enclave
make lkl-run

# Check the log file and decide if test passed
client_success=$(grep 'Remote connection established. Ready for service.' $ATTESTED_TLS_TEST_LOG_FILE | wc -l)
server_success=$(grep 'Server: attestation certificate verified.' $ATTESTED_TLS_TEST_LOG_FILE | wc -l)

cat $ATTESTED_TLS_TEST_LOG_FILE
if [[ $client_success -eq 1 && $server_success -eq 1 ]]; then
    echo "TEST PASSED"
    exit 0
fi
echo "TEST FAILED"
exit 1
