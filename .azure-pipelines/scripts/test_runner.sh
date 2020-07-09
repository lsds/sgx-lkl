#!/bin/bash
# This script must be invoked from the sgx-lkl-oe root directory.
# Parameters: None
# Usage: This script searches for 'Makefile' under the sgx-lkl-oe/test directory recursively, and invokes the global run_test.sh (test runner) on each.
# How is the test pass/fail outcome decided?
# Test will be failed if:
#   1. the exit code of run_test.sh is non-zero OR
#   2. stdout of run_test.sh contains one or more failure identifiers from $SGXLKL_ROOT/.azure-pipelines/other/failure_identifiers.txt (case sensitive).
# Based on the test result, junit files will be created (consumable by Azure/Jenkins CI pipelines).

#shellcheck disable=SC2002

if [ -z "$SGXLKL_ROOT" ]; then
    echo "ERROR: 'SGXLKL_ROOT' is undefined. Please export SGXLKL_ROOT=<SGX-LKL-OE> source code repository"
    exit 1
fi
if [ -z "$SGXLKL_BUILD_MODE" ]; then
    echo "ERROR: 'SGXLKL_BUILD_MODE' is undefined. Please export SGXLKL_BUILD_MODE=<mode>"
    exit 1
fi

#shellcheck source=.azure-pipelines/scripts/test_utils.sh
. "$SGXLKL_ROOT/.azure-pipelines/scripts/test_utils.sh"
#shellcheck source=.azure-pipelines/scripts/junit_utils.sh
. "$SGXLKL_ROOT/.azure-pipelines/scripts/junit_utils.sh"

# Runs make clean for the curren test folder
function CleanTest()
{
    test_directory=$(dirname "$file")
    ChangeDirectory "$test_directory"

    # Run make clean
    bash "$test_runner_script" "clean"
    ChangeDirectory "$SGXLKL_ROOT"
}

function RunOneTest()
{
    CheckNotRunning

    run_mode=$1

    echo "[Test #$counter/$total_tests] Found $file in directory $test_directory"
    ChangeDirectory "$test_directory"
    #shellcheck source=.azure-pipelines/scripts/run_test.sh
    . "$test_runner_script" init "$run_mode"
    echo "Test '$test_name' status - Running ($run_mode) ..."
    stdout_file="report/$test_name.stdout.txt"
    # Start the test timer. This only creates $test_name-StartTime file with time stamp in it
    JunitTestStarted "$test_name"

    # Start the test. Redirect stdout and stderr logs to stdout_file.
    # Test is run with unbuffered output streams to avoid losing errors in case of crashes.
    stdbuf -o0 -e0 "$test_runner_script" run "$run_mode" >"$stdout_file" 2>&1
    test_exit_code=$?
}

function ProcessOneTestResult()
{
    failures_in_output=0
    total_failures=0

    # Failure Analysis by searching stdout_file for some failure implying labels/identifiers
    current_test_failures=""
    for ((i = 0; i < ${#failure_identifiers[@]}; i++))
    do
        failure="${failure_identifiers[$i]}"
        echo "Checking for '$failure' in '$stdout_file' ..."
        current_output_failures=$(cat "$stdout_file" | grep "$failure" | grep -v -c "echo")
        total_failures=$((total_failures + current_output_failures))
        if [[ $current_output_failures -gt 0 ]]; then
            failure_string_in_output="Failure : '$failure' observed in '$stdout_file'"
            echo "$failure_string_in_output"
            current_test_failures+="$failure_string_in_output\n"
            failures_in_output=$((failures_in_output + current_output_failures))
        fi
    done

    # Copy last 50 lines of stdout into stacktrace for junit xml
    # Note: Azure DevOps supports only 4K characters in stack trace
    {
      echo "Note: Printing last 50 lines."
      echo "----------output-start-------------"
      cat "$stdout_file" | tail -50
      echo "----------output-end-------------" 
    } >> "$stack_trace_file_path"

    if [[ $test_exit_code -eq 0 && $failures_in_output -eq 0 ]]; then
        current_test_result="passed"
        total_passed=$((total_passed + 1))
    else
        current_test_result="failed"
        total_failed=$((total_failed + 1))
        for ((i = 0; i < ${#current_test_failures[@]}; i++))
        do
            echo -e "${current_test_failures[$i]}" >> "$stack_trace_file_path"
        done
        echo "Test '$test_name' status - $current_test_result (Exit code: '$test_exit_code'; FAILURES in output: '$failures_in_output')." > "$error_message_file_path"
    fi

    echo "-----------stdout-start-------------"
    cat "$stdout_file"
    echo "-----------stdout-end-------------"
    echo " "

    # Finalize the test case. This creates junit.xml file for the folder for test folder based summary reporting
    # If the test cases in the test folder doesn't create additional junit.xml files, this will be the only test report for the test folder.
    # Don't create test folder summary reporting for LTP since each LTP test case generates junit xml file and reports result
    # Non-LTP test folders doesn't do that so they need this folder based summary reporting junit xml
    JunitTestFinished "$test_name" "$current_test_result" "$test_class" "$test_suite"
    echo "Test '$test_name' status - $current_test_result (Exit code: '$test_exit_code'; FAILURES in output: '$failures_in_output')."
    echo "Test '$test_name' status - Completed."
    echo "Current Status: passed = $total_passed, failed = $total_failed, disabled = $total_disabled, remaining = $total_remaining."
    
    cp -ar report/* "$SGXLKL_ROOT/report"
    echo "Cleaning up $SGXLKL_ROOT/$test_directory/report"
    rm -rf "$SGXLKL_ROOT/$test_directory/report"
    ChangeDirectory "$SGXLKL_ROOT"
    echo ""
    echo "-------------------------------------------------------------"
    echo ""
}

# Increase counter by 1, set the reamining test count
# Also set test_directory using $file
function GetReadyToRunNextTest()
{
    counter=$((counter + 1))
    total_remaining=$((total_tests - counter))
    test_directory=$(dirname "$file")
}

function SkipTestIfDisabled()
{
    skip_test=false
    is_test_disabled=$(grep -c "$file" "$disabled_tests_file")
    if [[ $is_test_disabled -ge 1 ]]; then
        echo "Test $file is disabled. Skipping test..."
        echo "To enable the test remove $file from $disabled_tests_file"
    fi

    if [[ $is_test_disabled -eq 0 && ! -v SGXLKL_NIGHTLY_RUN ]]; then
        is_test_nightly_only=$(grep -c "$file" "$nightly_tests_file")
        if [[ $is_test_nightly_only -ge 1 ]]; then
            echo "Test $file is marked nighlty build only. Skipping test..."
            echo "To enable the test remove $file from $nightly_tests_file"
        fi
    fi

    # if this test is disabled set counters and skip to next test
    if [[ $is_test_disabled -ge 1 || $is_test_nightly_only -ge 1 ]]; then
        total_disabled=$((total_disabled + 1))
        counter=$((counter + 1))
        total_remaining=$((total_tests - counter))
        skip_test=true
    fi
}

test_folder_name="tests"
test_folder_identifier="Makefile"
test_runner_script="$SGXLKL_ROOT/.azure-pipelines/scripts/run_test.sh"
disabled_tests_file="$SGXLKL_ROOT/.azure-pipelines/scripts/disabled_tests.txt"
nighlty_tests_file="$SGXLKL_ROOT/.azure-pipelines/other/nighlty_run_only_tests.txt"
# test which needs not to be executed as part of CI e.g (test_name1\|test_name2...)
test_exception_list="ltp"

failure_identifiers_file="$SGXLKL_ROOT/.azure-pipelines/other/failure_identifiers.txt"
IFS=$'\n'

if [[ $1 == "ltp1" ]]; then
    file_list=("tests/ltp/ltp-batch1/Makefile")
    test_group_name="ltp-batch1"
elif [[ $1 == "ltp2" ]]; then
    file_list=("tests/ltp/ltp-batch2/Makefile")
    test_group_name="ltp-batch2"
elif [[ $1 == "core" ]]; then
    file_list=( $(find $test_folder_name -name $test_folder_identifier | grep -v "$test_exception_list") )
    test_group_name="core"
else
    echo "Unknown test suite: $1"
    exit 1
fi

total_tests=${#file_list[@]}

total_passed=0
total_failed=0
total_disabled=0
counter=0

# Record suite test start time
suite_test_start_time=$(date +%s)

failure_identifiers=()
while IFS= read -r line; do failure_identifiers+=("$line"); done < "$failure_identifiers_file"

for file in "${file_list[@]}";
do
    SkipTestIfDisabled
    if [[ $skip_test == true ]]; then 
        continue
    fi

    GetReadyToRunNextTest
    RunOneTest "$run_mode"
    ProcessOneTestResult

    # run "make clean" for current test folder
    CleanTest
done

echo "=====================TEST SUMMARY================="
echo "passed   = $total_passed"
echo "failed   = $total_failed"
echo "disabled = $total_disabled"
echo "total    = $total_tests"
echo "=================================================="

# Using suite test start time, create test duration junit xml which will be used for test duration in pipeline
if [[ "$test_group_name" == "core" ]]; then
    CreateSuiteTestRunDurationJunit "$suite_test_start_time" "$test_suite" "${test_group_name}-${SGXLKL_BUILD_MODE}-${run_mode}"
fi

# Subtract disabled tests before comparing toltal_passed
# Disabled tests not considered failure
total_tests=$((total_tests - total_disabled))
[[ $total_passed -eq $total_tests && $total_failed -eq 0  && $total_tests -gt 0 ]] && exit 0
exit 1
