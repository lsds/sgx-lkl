#!/bin/bash
if [ -z "$SGXLKL_ROOT" ]; then
    echo "ERROR: 'SGXLKL_ROOT' is undefined. Please export SGXLKL_ROOT=<SGX-LKL-OE> source code repository"
    exit 1
fi

#shellcheck source=.azure-pipelines/scripts/junit_utils.sh
. $SGXLKL_ROOT/.azure-pipelines/scripts/junit_utils.sh
#shellcheck source=.azure-pipelines/scripts/test_utils.sh
. $SGXLKL_ROOT/.azure-pipelines/scripts/test_utils.sh

SGXLKL_STARTER=${SGXLKL_STARTER:-$SGXLKL_ROOT/build/sgx-lkl-run-oe}

test_mode="$1"
case "$test_mode" in
    "run-hw")
	   echo "Will run tests for run-hw"
       run_flag="--hw-debug"
	   ;;
    "run-sw")
	   echo "Will run tests for run-sw"
       run_flag="--sw-debug"
	   ;;
    *)
	   echo "Invalid test_mode parameter: $test_mode. Valid options: run-hw/run-sw"
           exit 1;
	   ;;
esac
test_class="ltp"

SGXLKL_LTP_TSTAPP_CFG="--enclave-config=ltp_tstapp_enclave_config.json"
SGXLKL_LTP_HOST_CFG="--host-config=ltp_host_config.json"

SGX_LKL_RUN_CMD=( "$SGXLKL_STARTER" $SGXLKL_LTP_HOST_CFG $SGXLKL_LTP_TSTAPP_CFG $run_flag sgxlkl-miniroot-fs.img )

csv_filename="sgxlkl_oe_ltp_test_result_$(date +%d%m%y_%H%M%S).csv"
echo "SI No, Test Name, Stdout logfile name, Stderr logfile name, Execution Status" > "$csv_filename"

report_dir="report"
# Delete all files except ltp-batch(debug).* or ltp-batch(nonrelease).*
# Don't delete files that has paranthesis in file name
# Deleting this file causes problem in the parent test_runner.sh script
if [ -d $report_dir ]
then
    find $report_dir/ -type f -not -name '*\(*\)*' -delete
else
    mkdir $report_dir
fi

# Set variables
timeout=60
total_passed=0
total_failed=0
counter=0

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ltp_tests=($(grep -vf ./ltp_disabled_tests.txt  ./.c_binaries_list))
total_tests=${#ltp_tests[@]}

for file in "${ltp_tests[@]}"; do
    temp_test_name=${file}
    temp_test_name="${temp_test_name//.\//}"
    final_test_name="${temp_test_name//\//-}"
    counter=$((counter + 1))
    echo "[$counter/$total_tests] Running LTP test '$file' (Timeout = $timeout seconds)..."

    # Initialize the variables.
    test_name=${final_test_name#"-ltp-testcases-"}
    ltp_testcase_name=$(echo "${test_name%.*.*}" | sed 's/-/\//g; s/_/\//g')
    test_name="${test_name}-($SGXLKL_BUILD_MODE)-($test_mode)-($SGXLKL_ETHREADS-ethreads)"
    error_message_file_path="$report_dir/$test_name.error"
    stack_trace_file_path="$report_dir/$test_name.stack"
    stdout_file="$report_dir/$test_name.stdout.txt"
    # Start the test timer.
    JunitTestStarted "$test_name"

    # Master copy of image is sgxlkl-miniroot-fs.img.master
    # Before running each test copy a fresh copy of image
    rm -f sgxlkl-miniroot-fs.img
    cp sgxlkl-miniroot-fs.img.master sgxlkl-miniroot-fs.img
    cp_exit_code=$?
    if [[ $cp_exit_code -ne 0 ]]; then
      echo "Cannot find sgxlkl-miniroot-fs.img.master"
      exit 1
    fi

    echo "SGXLKL_CMDLINE=mem=512m SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 SGXLKL_TRACE_SIGNAL=1 timeout $timeout ${SGX_LKL_RUN_CMD[*]} $file > $stdout_file 2>&1"
    SGXLKL_CMDLINE="mem=512m" SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 SGXLKL_TRACE_SIGNAL=1 timeout $timeout "${SGX_LKL_RUN_CMD[@]}" "$file" > "$stdout_file" 2>&1
    exit_code=$?
    if [[ $exit_code -eq  124 ]]; then
        echo "${SGX_LKL_RUN_CMD[*]} $file : TIMED OUT after $timeout secs"
        echo "TIMED OUT after $timeout secs. TEST_FAILED" >> "$stdout_file"
    elif [[ $exit_code -ne 0 ]]; then
        echo "TEST_FAILED EXIT CODE: $exit_code" >> "$stdout_file"
    else
        echo "${SGX_LKL_RUN_CMD[*]} $file: RETURNED EXIT CODE: $exit_code"
    fi

    # Copy last 50 lines of stdout into stacktrace for junit xml
    # Note: Azure DevOps supports only 4K characters in stack trace
    {
        echo "Note: Printing last 50 lines."
        echo "----------output-start-------------"
        tail -50 < "$stdout_file"
        echo "----------output-end---------------"
    } > "$stack_trace_file_path"
    
    if [[ $exit_code -eq 0 ]]; then
        total_passed=$((total_passed + 1))
        echo "'$test_name' passed."
        echo "'$test_name' passed." > "$error_message_file_path"
        echo "$counter, $test_name, $stdout_file, Pass"
        echo "$counter, $ltp_testcase_name, $stdout_file, Pass" >> "$csv_filename"
        JunitTestFinished "$test_name" "passed" "$test_class" "$test_suite"
    else
        total_failed=$((total_failed + 1))
        echo "'$test_name' failed."
        echo "'$test_name' failed." > "$error_message_file_path"
        echo "'make $test_mode-single test=$file' can be used to test this individually failing ltp test"
        echo "'make $test_mode-single test=$file' can be used to test this individually failing ltp test" >> "$error_message_file_path"
        echo "$counter, $test_name, $stdout_file, Failed"
        echo "$counter, $ltp_testcase_name, $stdout_file, Failed" >> "$csv_filename"
        JunitTestFinished "$test_name" "failed" "$test_class" "$test_suite"
    fi
    echo "-------------------------------------------------------------------"
done
echo "Generating LTP failure test analysis report"
"$DIR/ltp_test_failure_analyzer"

echo "-------------------------------"
echo "Total passed  : $total_passed"
echo "Total failed  : $total_failed"
echo "-------------------------------"
echo "Total         : $total_tests"
echo "-------------------------------"
[[ $total_passed -eq $total_tests && $total_failed -eq 0 && $total_tests -gt 0 ]] && exit 0
exit 1
