#!/bin/bash

if [ -z $SGXLKL_ROOT ]; then
    echo "ERROR: 'SGXLKL_ROOT' is undefined. Please export SGXLKL_ROOT=<SGX-LKL-OE> source code repository"
    exit 1
fi

# TODO: add samples to code coverage measurement.
# For now, only measure anything under 'tests' except for LTP.
test_folder_name=$SGXLKL_ROOT/tests
test_folder_identifier="Makefile"
test_exception_list="ltp"

file_list=( $(sudo find $test_folder_name -name $test_folder_identifier | grep -v "$test_exception_list") )

total_tests=${#file_list[@]}
counter=0

rm -f $SGXLKL_ROOT/total_cov.info

for file in ${file_list[@]};
do
    counter=$(($counter + 1))
    folder=$(dirname $file)
    echo "$counter/$total_tests: Measuring code coverage in $folder"
    cd $folder
    $SGXLKL_ROOT/.azure-pipelines/scripts/measure_one_cov.sh
    make clean
done

echo "Done! All coverage data are aggregated to $SGXLKL_ROOT/total_cov.info"