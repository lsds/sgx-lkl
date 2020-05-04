#!/bin/bash

# Initialize 'report' directory.
mkdir -p report

# This function accepts only one arguement.
# Usage: If you want to record lapsed time during the test, 
#    Then, use below command to start the timer.
# PARAMETERS:
# Position 1: "Test Case Name" [MANDETORY]
# If test case name has space, then send the value in double quotes.
# eg. JunitTestStarted "make DEBUG=true"
function JunitTestStarted() 
{
    mkdir -p report
    test_name="$1"
    test_start_time_file_path="report/$test_name-StartTimeStamp"
    date +%s > "$test_start_time_file_path"
}

# Create test suite duration junit xml file
# Pass in test suite name start time in seconds
# CreateSuiteTestRunDurationJunit <suite start time> <test suite name> <test group name>
function CreateSuiteTestRunDurationJunit()
{
    suite_start_time=$1
    test_suite="$2"
    test_group_name="$3"
    suite_end_time=$(date +%s)
    junit_file_path="report/TEST-test-suite-test-run-overall-result-${test_group_name}-junit.xml"

    duration=$(($suite_end_time-$suite_start_time))

    echo "<testsuites>" > "$junit_file_path"
    echo "  <testsuite name=\"$test_suite\" duration=\"$duration\">" >> "$junit_file_path"
    echo "    <testcase name=\"test-suite-test-run-overall-result-${test_group_name}\" classname=\"Summary\" time=\"$duration\">" >> "$junit_file_path"
    echo "    </testcase>" >> "$junit_file_path"
    echo "  </testsuite>" >> "$junit_file_path"
    echo '</testsuites>' >> "$junit_file_path"
}

# If log file exists, read it, clean xml non-compliant characters
# then replace with place-holder in the junit xml file
# AddLogileToJunit <log file name> <junit xml file name> <place holder>
function AddLogFileToJunit()
{
    log_file="$1"
    junit_file="$2"
    place_holder="$3"

    # Add log file to junit if exist
    if [[ -f "$log_file" ]]; then
        FILE2=$(<"$junit_file")
        # Remove non-printable characters from log file
        FILE1=`sed 's/[^[:print:]]//g' "$log_file"`
        FILE1="${FILE1//\&/\&amp;}"
        FILE1="${FILE1//\"/\&quot;}"
        FILE1="${FILE1//\'/\&apos;}"
        FILE1="${FILE1//\</\&lt;}"
        FILE1="${FILE1//\>/\&gt;}"
        echo "${FILE2//$place_holder/$FILE1}" > "$junit_file"
    fi
}

# Usage: If you want to record the result in Azure Pipelines / Jenkins pipelines, then you need to record the results using this funtion.
# PARAMETERS:
# This function accepts MAX four arguments.
# It is mandatory to propvide these parameters in order and in double quotes if value has space in them.
# Position 1: "Test Case Name" [MANDETORY]
# Position 2: "Test Result" (passed/failed/aborted/skipped) [MANDETORY]
# Position 3: "Test Class Name" [Optional]
# Position 4: "Test Suite Name"  [Optional]
# Syntax: 
# JunitTestFinished "Test Name" "Test Result" "Test Class" "Test Suite"
# eg. JunitTestFinished "make DEBUG=true" "passed" "BVT" "sgx-lkl-oe"
function JunitTestFinished() 
{
    # Process the inputs.
    test_name="$1"
    test_result="$2"

    if [ -z "$3" ]; then
        echo "Warning: testclass value is not provided. Setting to 'Default'"
        test_class="Default"    
    else
        test_class=$3
    fi
    if [ -z "$4" ]; then
        echo "Warning: testsuite value is not provided. Setting to 'Default'"
        test_suite="Default"    
    else
        test_suite="$4"
    fi

    # Initialize variables.
    test_start_time_file_path="report/$test_name-StartTimeStamp"
    test_end_time_file_path="report/$test_name-EndTimeStamp"
    error_message_file_path="report/$test_name.error"
    stack_trace_file_path="report/$test_name.stack"
    stdout_file_path="report/$test_name.stdout.txt"
    stderr_file_path="report/$test_name.stderr.txt"
    junit_file_path="report/TEST-$test_name-junit.xml"
    date +%s > "$test_end_time_file_path"

    if [ -f "$test_start_time_file_path" ]; then 
        time_lapsed_in_seconds=$(($(cat "$test_end_time_file_path")-$(cat "$test_start_time_file_path")))
    else
        echo "Warning: Unable to calculate test runtime because you did not execute 'JunitTestStarted \"$test_name\" before running test.'"
        time_lapsed_in_seconds=0
    fi 
    


    echo '<testsuites>' > "$junit_file_path"
    echo "  <testsuite name=\"$test_suite\">" >> "$junit_file_path"
    echo "    <testcase name=\"$test_name\" classname=\"$test_class\" time=\"$time_lapsed_in_seconds\">" >> "$junit_file_path"
    if [[ "$test_result" != 'passed' ]]; then
        if [[ "$test_result" == 'failed' ]]; then
            failure_type="failure"
        elif [[ "$test_result" == 'aborted' ]]; then
            failure_type="error"
        elif [[ "$test_result" == 'skipped' ]]; then
            failure_type="skipped"
        fi
        echo "    <$failure_type  message=\"TEST_MESSAGE.\">STACK_TRACE</$failure_type>" >> "$junit_file_path"

        # Create error message file with this info if it doesn't exist
        if [ ! -f "$error_message_file_path" ]; then 
            echo "No message present. Please create '$error_message_file_path' containing your message to appear them here." > "$error_message_file_path"
        fi
        # Replace TEST_MESSAGE place holder with error message file
        AddLogFileToJunit "$error_message_file_path" "$junit_file_path" "TEST_MESSAGE"

	# Create stack trace file with this info if it doesn't exist
        if [ ! -f "$stack_trace_file_path" ]; then 
            echo "In case of failure, the output will be redirected here." > "$stack_trace_file_path"
        fi
	# Replace STACK_TRACE place holder with stack trace file
        AddLogFileToJunit "$stack_trace_file_path" "$junit_file_path" "STACK_TRACE"
    fi

    # Add stdout file to junit if exist
    if [[ -f "$stdout_file_path" ]]; then
        echo "      <system-out>STD_OUT_MESSAGE</system-out>" >> "$junit_file_path"
        AddLogFileToJunit "$stdout_file_path" "$junit_file_path" "STD_OUT_MESSAGE"
    fi

    # Add stderr file to junit if exist
    if [[ -f "$stderr_file_path" ]]; then
        echo "      <system-err>STD_ERR_MESSAGE</system-err>" >> "$junit_file_path"
        AddLogFileToJunit "$stderr_file_path" "$junit_file_path" "STD_ERR_MESSAGE"
    fi

    echo "    </testcase>" >> "$junit_file_path"
    echo "  </testsuite>" >> "$junit_file_path"
    echo '</testsuites>' >> "$junit_file_path"
    rm -f "$test_start_time_file_path"
    rm -f "$test_end_time_file_path"
    rm -f "$error_message_file_path"
    rm -f "$stack_trace_file_path"
    echo "INFO: Junit data recorded to '$junit_file_path'"
}
