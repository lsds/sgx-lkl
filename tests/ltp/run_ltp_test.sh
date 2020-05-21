#!/bin/bash
if [ -z $SGXLKL_ROOT ]; then
    echo "ERROR: 'SGXLKL_ROOT' is undefined. Please export SGXLKL_ROOT=<SGX-LKL-OE> source code repository"
    exit 1
fi

. $SGXLKL_ROOT/.azure-pipelines/scripts/junit_utils.sh
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

SGX_LKL_RUN_CMD="$SGXLKL_STARTER $run_flag sgxlkl-miniroot-fs.img"

csv_filename="sgxlkl_oe_ltp_test_result_$(date +%d%m%y_%H%M%S).csv"
echo "SI No, Test Name, Stdout logfile name, Stderr logfile name, Execution Status" > $csv_filename

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

current_failure_identifiers=()
while IFS= read -r line; do current_failure_identifiers+=("$line"); done < $DIR/failure_identifiers.txt

for file in ${ltp_tests[@]}; do
    temp_test_name=${file}
    temp_test_name="${temp_test_name//.\//}"
    final_test_name="${temp_test_name//\//-}"
    counter=$(($counter + 1))
    echo "[$counter/$total_tests] Running LTP test '$file' (Timeout = $timeout seconds)..."

    # Initialize the variables.
    test_name=${final_test_name#"-ltp-testcases-"}
    ltp_testcase_name=$(echo ${test_name%.*.*} | sed 's/-/\//g; s/_/\//g')
    test_name="${test_name}-($build_mode)-($test_mode)-($SGXLKL_ETHREADS-ethreads)"
    error_message_file_path="$report_dir/$test_name.error"
    stack_trace_file_path="$report_dir/$test_name.stack"
    stdout_file="$report_dir/$test_name.stdout.txt"
    stderr_file="$report_dir/$test_name.stderr.txt"
    # Start the test timer.
    JunitTestStarted "$test_name"

    echo "SGXLKL_CMDLINE=mem=512m SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 SGXLKL_TRACE_SIGNAL=1 timeout $timeout $SGX_LKL_RUN_CMD $file > \"$stdout_file\" 2> \"$stderr_file\""
    SGXLKL_CMDLINE="mem=512m" SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 SGXLKL_TRACE_SIGNAL=1 timeout $timeout $SGX_LKL_RUN_CMD $file > "$stdout_file" 2> "$stderr_file"
    exit_code=$?
    if [[ $exit_code -eq  124 ]]; then
        echo "$SGX_LKL_RUN_CMD $file : TIMED OUT after $timeout secs"
        echo "TIMED OUT after $timeout secs. TEST_FAILED" >> "$stderr_file"
    elif [[ $exit_code -ne 0 ]]
        echo "TEST_FAILED EXIT CODE: $exit_code" >> "$stderr_file"
    else
        echo "$SGX_LKL_RUN_CMD $file: RETURNED EXIT CODE: $exit_code"
    fi

    total_failures=0
    total_pass=0
    for ((i = 0; i < ${#current_failure_identifiers[@]}; i++))
    do
        failure="${current_failure_identifiers[$i]}"
        failure_count=$(cat "$stdout_file" | grep "$failure" | wc -l)
        total_failures=$(($total_failures + $failure_count))
        if [[ $failure_count -gt 0 ]]; then
            echo "Failure : '$failure' observed in '$stdout_file'"
        fi

        if [ ! -z $stderr_file ]; then
            failure_count=$(cat "$stderr_file" | grep "$failure" | wc -l)
            total_failures=$(($total_failures + $failure_count))
            if [[ $failure_count -gt 0 ]]; then
                echo "Failure : '$failure' observed in '$stderr_file'"
            fi
        fi
    done
    pass_count=$(cat "$stdout_file" "$stderr_file" | grep PASS | wc -l)
    if [[ $total_failures -eq 0 && $pass_count -eq  0 ]]; then
        echo "None of FAILURE IDENTIFIERS matched. Logs doesn't have PASS either. Assuming test FAILED. This can be false negative. Investigate. You can output  PASS to console in the test"
    fi
    if [[ $total_failures -eq 0 && $pass_count -gt 0 ]]; then
        total_passed=$(($total_passed + 1))
        echo "'$test_name' passed. Failure Count = $total_failures, Pass Count = $pass_count"
        echo "'$test_name' passed. Failure Count = $total_failures, Pass Count = $pass_count" > "$error_message_file_path"
        echo "$counter, $test_name, $stdout_file, $stderr_file, Pass"
        echo "$counter, $ltp_testcase_name, $stdout_file, $stderr_file, Pass" >> $csv_filename
        JunitTestFinished "$test_name" "passed" "$test_class" "$test_suite"
    else
        total_failed=$(($total_failed + 1))
        echo "'$test_name' failed. Failure Count = $total_failures, Pass Count = $pass_count"
        echo "'$test_name' failed. Failure Count = $total_failures, Pass Count = $pass_count" > "$error_message_file_path"
        echo "'make $test_mode-single test=$file' can be used to test this individually failing ltp test"
        echo "'make $test_mode-single test=$file' can be used to test this individually failing ltp test" >> "$error_message_file_path"
        echo "$counter, $test_name, $stdout_file, $stderr_file, Failed"
        echo "$counter, $ltp_testcase_name, $stdout_file, $stderr_file, Failed" >> $csv_filename
        if [ ! -z "$stderr_file" ]; then
            cat "$stderr_file" > "$stack_trace_file_path"
        else
            echo "Stack trace not available for $test_name." > "$stack_trace_file_path"
        fi

        JunitTestFinished "$test_name" "failed" "$test_class" "$test_suite"
    fi
    echo "-------------------------------------------------------------------"
done
echo "Generating LTP failure test analysis report"
$DIR/ltp_test_failure_analyzer

echo "-------------------------------"
echo "Total passed  : $total_passed"
echo "Total failed  : $total_failed"
echo "-------------------------------"
echo "Total         : $total_tests"
echo "-------------------------------"
[[ $total_passed -eq $total_tests && $total_failed -eq 0 && $total_tests -gt 0 ]] && exit 0
exit 1
