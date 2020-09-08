#!/bin/bash

# shellcheck source=/dev/null
source "../../common.sh"

test_mode=$1
run_mode=$2

set -e

if [[ "$test_mode" == "clean" ]]; then
    make clean
elif [[ "$test_mode" == "init" ]]; then
    "${SGXLKL_SETUP_TOOL}"
    make
elif [[ "$test_mode" == "run" ]]; then
    if [[ "$run_mode" == "run-hw" ]]; then
        ./run-hw.exp
    elif [[ "$run_mode" == "run-sw" ]]; then
        ./run-sw.exp
    fi
elif [[ "$test_mode" == "gettimeout" ]]; then
    # Default
    exit 1
fi

exit 0
