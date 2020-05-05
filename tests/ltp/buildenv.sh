#!/bin/bash

mode=$1
test_directory=$2

LTP_GIT_TAG="20190930"

if [ -z $test_directory ]; then
    echo "Please provide ltp tests directory. Example: ltp.sh 'testcases/kernel/syscalls'"
    exit 1
fi

if [[ "$mode" == "build" ]]; then
    cd /
    rm -rf /ltp
    echo "Installing depencancies..."
    apk update
    apk add alpine-sdk
    apk add make
    apk add build-dependencies build-base gcc wget git
    apk add automake
    apk add autoconf
    apk add linux-headers
    apk add glib
    apk add bison
    apk add flex
    apk add gawk
    apk add xz
    touch .c_binaries_list

    # Get the LTP source code
    echo "Cloning https://github.com/linux-test-project/ltp.git"
    git clone https://github.com/linux-test-project/ltp.git
    cd /ltp
    pwd=$(pwd)
    c_binaries_list_file_tmp="/$pwd/.c_binaries_list.tmp"
    c_binaries_list_file="/$pwd/.c_binaries_list"
    rm -rf $c_binaries_list_file
    touch $c_binaries_list_file

    git checkout $LTP_GIT_TAG
 
    echo "Apply the sgxlkl specific patches..." 
    git apply --verbose  --ignore-whitespace ../patches/*.patch

    echo "Running make clean..."
    make autotools
    ./configure
    make clean > /dev/null 2> /dev/null

    
    pass_file="$pwd/passed_test.txt"
    fail_file="$pwd/failed_test.txt"
    echo "" > $pass_file
    echo "" > $fail_file

    IFS=$'\n'
    file_list=( $(find $test_directory -name Makefile) )

    makefile_counter=$(find $test_directory -name Makefile | wc -l)
    counter=0
    c_binaries_counter=0
    c_binaries_failures=0

    echo "Compling and generating binaries in $test_directory recursively"
    for file in ${file_list[@]};
    do
        current_test_directory=$(dirname $file)
        counter=$(($counter + 1))
        printf '%-17s' "[Test #$counter/$makefile_counter]"
        cd $current_test_directory
        c_file_list=( $(find . -name "*.c") )
        printf '%-70s' "Building $current_test_directory "
        make 1> build.log 2>&1
        if [[ $? == 0 ]]; then
                printf '%-10s\n' "Success"
                for c_file in ${c_file_list[@]};
                do
                        filename="${c_file%.*}"
                        if [ -f $filename ];then
                            c_binaries_counter=$(($c_binaries_counter + 1))
                            echo "$current_test_directory/$filename" >> $c_binaries_list_file_tmp
                        else
                            echo -e "\t \t WARNING !! $filename is not generated"
                        fi
                done
        else
                printf '%-10s\n' "Failed"
                echo "_________________________________________"
                cat build.log
                echo -e "_________________________________________\n"
                c_binaries_failures=$(($c_binaries_failures + 1))
        fi
        [ -f build.log ] && rm -f build.log
        cd $pwd
    done
    sed 's/\.\///' -i $c_binaries_list_file_tmp
    cat $c_binaries_list_file_tmp | sort | uniq  > $c_binaries_list_file
    rm -f $c_binaries_list_file_tmp
    echo "--------------------------------------------------------------"
    echo "Generated $c_binaries_counter binaries in $test_directory"
    echo $c_binaries_counter > .c_binaries_counter
    echo "Failed to generate $c_binaries_failures binaries in $test_directory"
    echo "--------------------------------------------------------------"
fi

if [[ "$mode" == "run" ]];then
    cd /ltp
    pwd=$(pwd)
    c_binaries_list_file="$pwd/.c_binaries_list"    
    file_list=( $(find $test_directory -name Makefile) )
    makefile_counter=$(find $test_directory -name Makefile | wc -l)
    
    counter=0    
    pass_file="$pwd/passed_test.txt"
    fail_file="$pwd/failed_test.txt"
    echo "" > $pass_file
    echo "" > $fail_file
    c_binaries_counter=$(cat .c_binaries_counter)
    echo "Running the tests using generated binaries in $test_directory recursively"
    counter=0
    for file in ${file_list[@]};
    do
        current_test_directory=$(dirname $file)
        cd $current_test_directory
        c_file_list=( $(find . -name "*.c") )
        for c_file in ${c_file_list[@]};
        do
            filename="${c_file%.*}"
            if [ ! -z $filename ]; then
                counter=$(($counter + 1))
                echo "[Test #$counter/$c_binaries_counter] Running $filename in directory $current_test_directory ..."
                $filename
                if [[ "$?" == "0" ]]; then
                        echo "$current_test_directory/$filename" >> $pass_file
                else
                        echo "$current_test_directory/$filename" >> $fail_file
                fi
            fi
        done
        cd $pwd
    done
fi
