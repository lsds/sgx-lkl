#!/bin/bash

if [ -z $SGXLKL_ROOT ]; then
    echo "ERROR: 'SGXLKL_ROOT' is undefined. Please export SGXLKL_ROOT=<SGX-LKL-OE> source code repository"
    exit 1
fi

. /opt/openenclave/share/openenclave/openenclaverc
. $SGXLKL_ROOT/.azure-pipelines/scripts/junit_utils.sh
. $SGXLKL_ROOT/.azure-pipelines/scripts/test_utils.sh

# Initialize the variables and test case [mandatory].
test_mode=$1
run_mode=$2
[[ -z $test_mode ]] && test_mode="run"
[[ -z $run_mode ]] && run_mode="run"

# make clean
if [[ "$test_mode" == "clean" ]]; then
    make clean
    exit $?
fi

test_name="$(basename $(pwd))-($build_mode)"
[[ "$run_mode" == "run-hw" || "$run_mode" == "run-sw" ]] && test_name+="-($run_mode)"
test_class=$(basename $(dirname $(pwd)))
test_suite="sgx-lkl-oe"

if [[ -z $test_name || -z $test_class || -z $test_mode ]]; then
    echo -e "\n ERROR: test_name test_class or test_mode not passed \n"
    exit 1
fi

if [[ "$test_mode" == "init" ]]; then
    InitializeTestCase "$test_name" "$test_class" "$test_suite" "$test_mode"
    return 0
fi

# Get the timeout from the test module
DEFAULT_TIMEOUT=300
timeout=$(make gettimeout 2> /dev/null)
[[ $? != 0 ]] && timeout=$DEFAULT_TIMEOUT
echo "Execution timeout: $timeout"

case "$test_mode" in
    "run")
	   echo "Will run tests for both run-hw and run-sw" 
	   ;;
    "run-hw")
	   echo "Will run tests for run-hw"
	   ;;
    "run-sw")
	   echo "Will run tests for run-sw"
	   ;;
    *)
	   echo "Invalid test_mode parameter: $test_mode. Valid options: run/run-hw/run-sw"
           exit 1;
	   ;;
esac

make_sw_exit=0
make_hw_exit=0

if [[ "$test_mode" == "run" || "$test_mode" == "run-sw" ]]; then
    timeout --kill-after=$(($timeout + 15))  $timeout make run-sw
    make_sw_exit=$?

    if [[ "$make_sw_exit" == "124" ]]; then
        echo "make run-sw: TIMED OUT after $timeout secs"
    elif [[ "$make_sw_exit" != "0" ]]; then
        echo "make run-sw: FAILED WITH EXIT CODE: $make_sw_exit"
    fi
fi

if [[ "$test_mode" == "run" || "$test_mode" == "run-hw" ]]; then
    timeout --kill-after=$(($timeout + 15))  $timeout make run-hw
    make_hw_exit=$?

    if [[ "$make_hw_exit" == "124" ]]; then
        echo "make run-hw: TIMED OUT after $timeout secs"
    elif [[ "$make_hw_exit" != "0" ]]; then
        echo "make run-hw: FAILED WITH EXIT CODE: $make_hw_exit"
    fi
fi

make_exit=1
[[ $make_sw_exit -eq 0 && $make_hw_exit -eq 0 ]] && make_exit=0
echo "Test run completed with EXIT CODE $make_exit"

exit $make_exit
