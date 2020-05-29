#!/bin/bash

function InitializeTestCase()
{
    # Initialize the variables.
    test_name=$1
    test_class=$2
    test_suite=$3
    test_mode=$4
    error_message_file_path="report/$test_name.error"
    stack_trace_file_path="report/$test_name.stack"
    echo "Initialized test_name=$test_name"
    echo "Initialized test_class=$test_class"
    echo "Initialized test_suite=$test_suite"
    echo "Initialized error_message_file_path=$error_message_file_path"
    echo "Initialized stack_trace_file_path=$stack_trace_file_path"  
}

function ChangeDirectory()
{
    test_directory="$1"
    echo "Changing directory to $test_directory"
    cd "$test_directory"
}

function CheckNotRunning()
{
    process="sgx-lkl-run-oe"
    if pgrep -x $process >/dev/null; then
        echo "SGX-LKL still running:"
        ps -aux | grep $process
        echo "Trying to kill hanging $process process"
        pkill -9 $process
        pkill_exit=$?
        if [[ $pkill_exit -ne 0 ]]; then
            echo "Failed to kill hanging $process process. Exit code: $pkill_exit"
            exit $pkill_exit
        else
	    echo "Killed the hanging $process process successfully"
	    ps -aux | grep sgx-lkl-run-oe
        fi
    fi
}
