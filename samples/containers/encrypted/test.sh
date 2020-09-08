#!/bin/bash

test_mode=$1
run_mode=$2

set -e

if [[ "$test_mode" == "clean" ]]; then
    make clean
elif [[ "$test_mode" == "init" ]]; then
    make
elif [[ "$test_mode" == "run" ]]; then
    make "$run_mode"-verity
    # TODO: This doesn't work
    #make "$run_mode"-integrity
elif [[ "$test_mode" == "gettimeout" ]]; then
    # Default
    exit 1
fi

exit 0
