#!/bin/bash

test_mode=$1

set -e

if [[ "$test_mode" == "clean" ]]; then
    make clean
elif [[ "$test_mode" == "init" ]]; then
    echo "Nothing to do"
elif [[ "$test_mode" == "run" ]]; then
    make
elif [[ "$test_mode" == "gettimeout" ]]; then
    # Default
    exit 1
fi

exit 0
