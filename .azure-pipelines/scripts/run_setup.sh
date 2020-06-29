#!/bin/bash

# Set up host networking and FSGSBASE userspace support
make -C "$SGXLKL_ROOT/tools/kmod-set-fsgsbase"
"$SGXLKL_ROOT/tools/sgx-lkl-setup"
