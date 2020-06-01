SGX-LKL Testing
===============

How to run LTP tests
--------------------

To be able to run one or all LTP tests, SGX-LKL must have been built and installed according to the instructions in [README.md](../README.md).

## Running all LTP tests

LTP tests are partitioned into several batches for parallel execution in the [CI pipeline](https://dev.azure.com/sgx-lkl/sgx-lkl/_build).
LTP test batch folders are in [`tests/ltp`](../tests/ltp).
Depending on which batch you like to run, switch to the corresponding folder, for example [`tests/ltp/ltp-batch1`](../tests/ltp/ltp-batch1).
Then run:
```
make clean
DEBUG=true make
make run

# This will run all 200+ LTP tests in ltp-batch1 for run-hw and run-sw modes. 
# It takes around 8 seconds to run each test. It will take around 30 minutes to finish tests for each mode.

# You can also run tests just for one mode:
make run-hw
make run-sw
```

## Running one LTP test

```
# This will build and create an image but will not run any test. This image is required to run any LTP test
make clean
make sgxlkl-miniroot-fs.img

# /opt/sgx-lkl/bin/ prefix is optional for commands sgx-lkl-run-oe and sgx-lkl-gdb below if added to $PATH

# Running single test without gdb:
make run-hw-single test=/ltp/testcases/kernel/syscalls/chmod/chmod06
make run-sw-single test=/ltp/testcases/kernel/syscalls/chmod/chmod06

# Running single test with gdb:
make run-hw-single-gdb test=/ltp/testcases/kernel/syscalls/chmod/chmod06
make run-sw-single-gdb test=/ltp/testcases/kernel/syscalls/chmod/chmod06

# Running single test with gdb with more trace details:
SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 SGXLKL_TRACE_LKL_SYSCALL=1 SGXLKL_TRACE_MMAP=1 \
    make run-hw-single-gdb test=/ltp/testcases/kernel/syscalls/chmod/chmod06
```

## Mounting SGX-LKL image to look at test case source code

```
# Create a directory under tests/ltp/ltp-batch1
mkdir mountdir

# Mount image to this folder 
sudo mount -t ext4 -o loop sgxlkl-miniroot-fs.img  mountdir

# You will need admin permission to see the content of mounted image
# Below command will change your current folder to /root
# Change your directory back to sgx-lkl root folder after running this command
sudo su - 

# Now you can see image folders
cd tests/ltp/ltp-batch1/mountdir

# LTP test cases are available under ltp/testcases/kernel/syscalls
cd ltp/testcases/kernel/syscalls

# Exit from admin/sudo mode
exit
```
