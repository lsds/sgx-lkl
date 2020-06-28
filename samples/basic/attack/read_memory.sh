#!/bin/bash

set -e

program=$1
search_string=$2
save_pid=$(pidof "$program" || echo "")
if [[ "$save_pid" == "" ]]; then
    echo "Process '$program' not found"
    exit 1
fi

echo "Saving memory image of process ${save_pid}..."

sudo gcore -o mem.dump "${save_pid}" >/dev/null 2>&1
mem_files=(mem.dump.*)

mem_file=${mem_files[0]}

sudo chown "$(id -u -n):$(id -g -n)" "$mem_file"

echo "Searching memory for string \"${search_string}\" in \"${mem_file}\"..."

if (strings "${mem_file}" | grep -i "${search_string}"); then
        echo Match found.
else
        echo No match found.
fi

rm "$mem_file"
