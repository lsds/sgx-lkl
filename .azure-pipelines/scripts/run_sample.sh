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
sample_mode=$1 # clean, init or run
run_mode=$2 # run-hw or run-sw

if [[ "$sample_mode" == "clean" ]]; then
    ./test.sh clean
    exit $?
fi

samples_dir=$SGXLKL_ROOT/samples
sample_name="$(realpath --relative-to="$samples_dir" "$(pwd)")"
sample_name="${sample_name//\//-}"
sample_name+="-($SGXLKL_BUILD_MODE)-($run_mode)-($SGXLKL_ETHREADS-ethreads)"
sample_class=$(realpath --relative-to="$samples_dir" "$(pwd)/..")
test_suite="sgx-lkl-oe"

if [[ -z $sample_name || -z $sample_class || -z $sample_mode ]]; then
    echo -e "\n ERROR: sample_name sample_class or sample_mode not passed \n"
    exit 1
fi

if [[ "$sample_mode" == "init" ]]; then
    InitializeTestCase "$sample_name" "$sample_class" "$test_suite" "$run_mode"
fi

# Get the timeout from the test module
DEFAULT_TIMEOUT=300
if ! timeout=$(./test.sh gettimeout 2> /dev/null); then
    timeout=$DEFAULT_TIMEOUT
fi
echo "Execution timeout: $timeout"

case "$run_mode" in
    "run-hw")
       echo "Will run samples for run-hw"
       ;;
    "run-sw")
       echo "Will run samples for run-sw"
       ;;
    *)
       echo "Invalid run_mode parameter: $run_mode. Valid options: run-hw/run-sw"
       exit 1;
       ;;
esac

if [[ $sample_mode == "init" ]]; then
    timeout --kill-after=$((timeout + 60)) $timeout ./test.sh init
    script_exit=$?
elif [[ $sample_mode == "run" ]]; then
    timeout --kill-after=$((timeout + 60)) $timeout ./test.sh run "$run_mode"
    script_exit=$?
else
    echo "Invalid sample_mode parameter: $sample_mode. Valid options: clean/init/run/gettimeout"
    exit 1
fi

if [[ "$script_exit" == "124" ]]; then
    echo "$run_mode: TIMED OUT after $timeout secs"
elif [[ "$script_exit" != "0" ]]; then
    echo "$run_mode: FAILED WITH EXIT CODE: $script_exit"
fi

if [[ $sample_mode == "init" ]]; then
    echo "Sample initialization completed with EXIT CODE $script_exit"
    return $script_exit
fi

echo "Sample run completed with EXIT CODE $script_exit"

exit $script_exit
