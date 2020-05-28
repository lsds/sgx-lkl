#!/bin/bash

export PATH="../../../tools:$PATH"

sgx-lkl-disk create --docker=Dockerfile --size=300M disk.img
sgx-lkl-cfg create --disk disk.img
