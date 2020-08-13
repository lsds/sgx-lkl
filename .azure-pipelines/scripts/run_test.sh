#!/bin/bash

if [ -z "$SGXLKL_ROOT" ]; then
    echo "ERROR: 'SGXLKL_ROOT' is undefined. Please export SGXLKL_ROOT=<SGX-LKL-OE> source code repository"
    exit 1
fi
if [ -z "$SGXLKL_BUILD_MODE" ]; then
    echo "ERROR: 'SGXLKL_BUILD_MODE' is undefined. Please export SGXLKL_BUILD_MODE=<mode>"
    exit 1
fi

#shellcheck source=.azure-pipelines/scripts/junit_utils.sh
. "$SGXLKL_ROOT/.azure-pipelines/scripts/junit_utils.sh"
#shellcheck source=.azure-pipelines/scripts/test_utils.sh
. "$SGXLKL_ROOT/.azure-pipelines/scripts/test_utils.sh"

# Initialize the variables and test case [mandatory].
test_mode=$1 # init or run
run_mode=$2 # run-hw or run-sw

# make clean
if [[ "$test_mode" == "clean" ]]; then
    make clean
    exit $?
fi

tests_dir=$SGXLKL_ROOT/tests
test_name="$(realpath --relative-to="$tests_dir" "$(pwd)")"
test_name="${test_name//\//-}"
test_name+="-($SGXLKL_BUILD_MODE)-($run_mode)-($SGXLKL_ETHREADS-ethreads)"
test_class=$(realpath --relative-to="$tests_dir" "$(pwd)/..")
test_suite="sgx-lkl-oe"

if [[ -z $test_name || -z $test_class || -z $test_mode ]]; then
    echo -e "\n ERROR: test_name test_class or test_mode not passed \n"
    exit 1
fi

if [[ "$test_mode" == "init" ]]; then
    InitializeTestCase "$test_name" "$test_class" "$test_suite" "$run_mode"
    return 0
fi

# Get the timeout from the test module
DEFAULT_TIMEOUT=300
if ! timeout=$(make gettimeout 2> /dev/null); then
    timeout=$DEFAULT_TIMEOUT
fi
echo "Execution timeout: $timeout"

case "$run_mode" in
    "run-hw")
       echo "Will run tests for run-hw"
       ;;
    "run-sw")
       echo "Will run tests for run-sw"
       ;;
    *)
       echo "Invalid run_mode parameter: $run_mode. Valid options: run-hw/run-sw"
       exit 1;
       ;;
esac

timeout --kill-after=$((timeout + 60)) $timeout make "$run_mode"
make_exit=$?

if [[ "$make_exit" == "124" ]]; then
    echo "make $run_mode: TIMED OUT after $timeout secs"
elif [[ "$make_exit" != "0" ]]; then
    echo "make $run_mode: FAILED WITH EXIT CODE: $make_exit"
fi

echo "Test run completed with EXIT CODE $make_exit"

exit $make_exit
