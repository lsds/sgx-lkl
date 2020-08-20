#!/bin/bash

#shellcheck disable=SC2002,SC2164

mode=$1
test_directory=$2

# All LTP test folders are under ltp/testcases/kernel/syscalls/
# All enabled LTP tests are specified in ltp_disabled_tests.txt under tests/ltp/ltp-batch1 and tests/ltp/ltp-batch2
# In this function we are creating /ltp_folders_skipped.txt which has folders that has no enabled LTP test
function CreateNotEnabledLtpTestFoldersListFile()
{
    grep '#' "/tests/ltp/ltp-batch1/ltp_disabled_tests.txt" > "/enabled_ltp_tests.txt"
    grep '#' "/tests/ltp/ltp-batch2/ltp_disabled_tests.txt" >> "/enabled_ltp_tests.txt"

    # Get the unique syscall list that LTP test suite addresses
    cur_folder=$(pwd)
    cd "/ltp/testcases/kernel/syscalls"
    ls -ld */  | sed 's/.* \(.*\)\//\1/g' | sort | uniq > "/ltp_folders.txt"
    cd $cur_folder

    rm -fr "/ltp_folders_enabled_tmp.txt"

    # Get the unique syscall list that enabled in sgx-lkl
    while IFS= read -r line
    do
       sed -e 's/#\/ltp\/testcases\/kernel\/syscalls\/\(.*\)\/.*/\1/g' <<< $line >>"/ltp_folders_enabled_tmp.txt"
    done<"/enabled_ltp_tests.txt"

    # Get the difference of above 2 lists to get the syscall list that zero LTP test enabled
    # We will not build these folders since there will be no LTP test running against them
    sort "/ltp_folders_enabled_tmp.txt" | uniq > "/ltp_folders_enabled.txt"
    comm -3 "/ltp_folders.txt" "/ltp_folders_enabled.txt"  > "/ltp_folders_skipped.txt"
}

if [ -z "$test_directory" ]; then
    echo "Please provide ltp tests directory. Example: ltp.sh 'testcases/kernel/syscalls'"
    exit 1
fi

if [[ "$mode" == "build" ]]; then
    cd /
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

    # LTP folder is a submodule and copied into image
    cd /ltp
    pwd=$(pwd)
    c_binaries_list_file_tmp="/$pwd/.c_binaries_list.tmp"
    c_binaries_list_file="/$pwd/.c_binaries_list"
    rm -rf "$c_binaries_list_file"
    touch "$c_binaries_list_file"

 
    echo "Running make clean..."
    make autotools
    ./configure
    make clean > /dev/null 2> /dev/null

    
    pass_file="$pwd/passed_test.txt"
    fail_file="$pwd/failed_test.txt"
    echo "" > "$pass_file"
    echo "" > "$fail_file"

    IFS=$'\n'
    file_list=( $(find "$test_directory" -maxdepth 2 -name Makefile) )

    makefile_counter=$(find "$test_directory" -name Makefile | wc -l)
    # syscall folder counts
    counter_total=0
    counter_skip=0
    counter_fail=0
    counter_success=0
    # syscall test counts, a folder can have multiple tests (c files)
    c_binaries_total=0
    c_binaries_skip=0
    c_binaries_fail=0
    c_binaries_success=0

    # This function will generate /ltp_folders_skipped.txt
    # If a syscall folder exists in /ltp_folders_skipped.txt, it means there is no LTP test enabled
    # and it will not be built, it will be skipped
    CreateNotEnabledLtpTestFoldersListFile

    echo "Compling and generating binaries in $test_directory recursively"
    for file in "${file_list[@]}";
    do
        current_test_directory=$(dirname "$file")
        counter_total=$((counter_total + 1))
        cd "$current_test_directory"
        printf '%-17s' "[Test #$counter_total/$makefile_counter]"

        c_file_list=( $(find . -maxdepth 1 -name "*.c") )
        c_file_count=${#c_file_list[@]}
        c_binaries_total=$((c_binaries_total + c_file_count))

        folder_name=$(sed -e 's/\/ltp\/testcases\/kernel\/syscalls\/\(.*\)/\1/g' <<< $current_test_directory)
        # if matches, this syscall folder will be skipped since no LTP test enabled in it
        match_count=$(grep -c -w $folder_name "/ltp_folders_skipped.txt")
        if [[ $match_count -ge 1 ]]; then
	    printf '%-70s' "Skipping $current_test_directory "
	    printf '%-10s\n' "Skipped"
	    counter_skip=$((counter_skip + 1))
	    c_binaries_skip=$((c_binaries_skip + c_file_count))
	    continue
        else
            printf '%-70s' "Building $current_test_directory "
            if make 1> build.log 2>&1 ; then
                counter_success=$((counter_success + 1))
                printf '%-10s\n' "Success"
                for c_file in "${c_file_list[@]}";
                do
                        filename="${c_file%.*}"
                        if [ -f "$filename" ];then
                            c_binaries_success=$((c_binaries_success + 1))
                            echo "$current_test_directory/$filename" >> "$c_binaries_list_file_tmp"
                        else
                            c_binaries_fail=$((c_binaries_fail + 1))
                            echo -e "\t \t WARNING !! $filename is not generated"
                        fi
                done
            else
                printf '%-10s\n' "Failed"
                echo "_________________________________________"
                cat build.log
                echo -e "_________________________________________\n"
                counter_fail=$((counter_fail + 1))
                c_binaries_fail=$((c_binaries_fail + c_file_count))
            fi

            [ -f build.log ] && rm -f build.log
	fi
	cd "$pwd"
    done

    sed 's/\.\///' -i "$c_binaries_list_file_tmp"
    cat "$c_binaries_list_file_tmp" | sort | uniq  > "$c_binaries_list_file"
    rm -f "$c_binaries_list_file_tmp"
    echo "---------------------------------------------------------------------------------"
    echo "Syscalls/Folders => Total: $counter_total, Success: $counter_success, Fail: $counter_fail, Skip: $counter_skip"
    echo "Tests/Binaries   => Total: $c_binaries_total, Success: $c_binaries_success, Fail: $c_binaries_fail, Skip: $c_binaries_skip"
    echo ""
    echo "Generated $c_binaries_success/$c_binaries_total binaries in $counter_success/$counter_total folders in $test_directory"
    echo "Skipped $c_binaries_skip/$c_binaries_total binaries in $counter_skip/$counter_total folders since LTP tests not enabled"
    echo "Failed to generate $c_binaries_fail/$c_binaries_total binaries in $counter_fail/$counter_total folders"
    echo "---------------------------------------------------------------------------------"
    echo $c_binaries_success > .c_binaries_counter
fi

if [[ "$mode" == "run" ]];then
    cd /ltp
    pwd=$(pwd)
    c_binaries_list_file="$pwd/.c_binaries_list"    
    file_list=( $(find "$test_directory" -name Makefile) )
    makefile_counter=$(find "$test_directory" -name Makefile | wc -l)
    
    counter=0    
    pass_file="$pwd/passed_test.txt"
    fail_file="$pwd/failed_test.txt"
    echo "" > "$pass_file"
    echo "" > "$fail_file"
    c_binaries_counter=$(cat .c_binaries_counter)
    echo "Running the tests using generated binaries in $test_directory recursively"
    counter=0
    for file in "${file_list[@]}";
    do
        current_test_directory=$(dirname "$file")
        cd "$current_test_directory"
        c_file_list=( $(find . -name "*.c") )
        for c_file in "${c_file_list[@]}";
        do
            filename="${c_file%.*}"
            if [ ! -z "$filename" ]; then
                counter=$((counter + 1))
                echo "[Test #$counter/$c_binaries_counter] Running $filename in directory $current_test_directory ..."
                if $filename; then
                        echo "$current_test_directory/$filename" >> "$pass_file"
                else
                        echo "$current_test_directory/$filename" >> "$fail_file"
                fi
            fi
        done
        cd "$pwd"
    done
fi
