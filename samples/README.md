### Sample programs to demonstrate SGX-LKL functionality

1. basic
   1. [helloworld](basic/helloworld)
   Cross-compile a C application for running with SGX-LKL
   Simple hello world C program run in sgx-lkl
    
    b.dynamic_loading:
        Shared library test 
        A program calls a function from another file within a secure enclave 
        Shared library is compiled into a shared object and the program into a binary. They are both transferred into a folder within the new image created and the folder is mounted
    
2. containers
   
    a. [alpine](containers/alpine)
        Miniroot is a quick way of building a small Alpine disk image, appropriate for
use with sgx-musl hosting redis.
        Some basic packages are installed by default and additions can be made
    
    b. [encrypted](containers/encrypterd)
        Running an Encrypted and Integrity Protected Confidential Container with SGX-LKL. This sample created an encrypted image using a AES cipher and creates keys. You can run python applications in the container using `dm-integrity` and `dm-verity`

        Prints hello world from an encrypted confidential container

        run hw/sw variety -  success/problem changing owners while mounting
        run hw/sw integrity - problem activating crypto disk 

    c. [redis](containers/redis)

        Build redis file system within SGX-LKL and experiment with the redis-cli commands in this enclave 

1. languages
   
    a. [dotnet](languages/dotnet)
        Run a hello-world .NET progream within an SGX-LKL image hosted in a docker container

    b. [java](languages/java)
        Run a hello-world program written in java from within SGX-LKL.

    c. [openmp](languages/openmp)
         FAIL: Encountered an illegal instruction inside enclave (opcode=0x50f)
         (as soon as it says running 8 threads)

    d. [python](languages/python)
        Run a small python application within SGX-LKL. Uses pythons numpy to display numbers from 0 to 9999. Uses alpine as the root image.

2. ml
   
    a. openvino

    b. pytorch 

    c. tensorflow