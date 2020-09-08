#!/bin/bash

# shellcheck source=/dev/null
source "../../common.sh"

DISK_IMAGE=pythonapp.img

test_mode=$1
run_mode=$2

set -e

if [[ "$test_mode" == "clean" ]]; then
    rm "$DISK_IMAGE"
elif [[ "$test_mode" == "init" ]]; then
    docker build -t pythonapp .
    docker run --rm pythonapp
elif [[ "$test_mode" == "run" ]]; then
    "${SGXLKL_DISK_TOOL}" create --force --docker=pythonapp \
            --size=300M "${DISK_IMAGE}"
    "${SGXLKL_CFG_TOOL}" create --disk "${DISK_IMAGE}"
    if [[ "$run_mode" == "run-hw" ]]; then
        "${SGXLKL_STARTER}" --host-config=host-config.json \
                --enclave-config=enclave-config.json --hw-debug
    elif [[ "$run_mode" == "run-sw" ]]; then
        "${SGXLKL_STARTER}" --host-config=host-config.json \
                --enclave-config=enclave-config.json --sw-debug
    fi
elif [[ "$test_mode" == "gettimeout" ]]; then
    # Default
    exit 1
fi

exit 0
