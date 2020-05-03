#!/bin/bash

set -e

echo "CPU info:"
lscpu
echo
echo "Available memory:"
free -h
echo
echo "Available disk space:"
df -h
echo
echo "Distribution:"
lsb_release -ds
echo
echo "SGX kernel module:"
modinfo intel_sgx || echo "none"
echo
echo "Running SGX-LKL instances:"
ps -aux | grep sgx-lkl-run-oe | grep -v grep || echo "none"
echo
echo "Environment variables:"
printenv | sort
