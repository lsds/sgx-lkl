#!/bin/bash

# shellcheck source=/dev/null
source "../../common.sh"

test_mode=$1
run_mode=$2

set -e

if [[ "$test_mode" == "clean" ]]; then
    rm -f rootfs.img rootfs.img.docker rootfs.img.key
elif [[ "$test_mode" == "init" ]]; then
    rm -f mem.dump.*
    docker build -t attackme .
elif [[ "$test_mode" == "run" ]]; then
    if [[ "$run_mode" == "run-sw" ]]; then
        ./plain-docker.exp
    elif [[ "$run_mode" == "run-hw" ]]; then
        ./sgx.exp
    fi
elif [[ "$test_mode" == "gettimeout" ]]; then
    # 20 minutes
    echo 1200
fi

exit 0
