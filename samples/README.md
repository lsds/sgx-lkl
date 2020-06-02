### Sample programs to demonstrate SGX-LKL functionality

1. Basic
   
   a. [Helloworld](basic/helloworld) <br>
   Cross-compile a C application for running with SGX-LKL
   Simple hello world C program run in sgx-lkl
    
2. Containers
   
    a. [Alpine](containers/alpine) <br>
        Miniroot is a quick way of building a small Alpine disk image, appropriate for use with sgx-musl hosting redis.
        Some basic packages are installed by default and additions can be made
    
    b. [Encrypted](containers/encrypted) <br>
        Running an Encrypted and Integrity Protected Confidential Container with SGX-LKL. This sample created an encrypted image using a AES cipher and creates keys. You can run python applications in the container using `dm-integrity` and `dm-verity`
        Prints hello world from an encrypted confidential container <br>
        FAIL: <br>
        run hw/sw variety -  success/problem changing owners while mounting <br>
        run hw/sw integrity - problem activating crypto disk

    c. [Redis](containers/redis) <br>
        Build redis file system within SGX-LKL and experiment with the redis-cli commands in this enclave 

1. Languages
   
    a. [Dotnet](languages/dotnet) <br>
        Run a hello-world .NET progream within an SGX-LKL image hosted in a docker container

    b. [Java](languages/java) <br>
        Run a hello-world program written in java from within SGX-LKL.

    c. [Openmp](languages/openmp) <br>
        FAIL: Encountered an illegal instruction inside enclave (opcode=0x50f)
        (as soon as it says running 8 threads)

    d. [Python](languages/python) <br>
        Run a small python application within SGX-LKL. Uses pythons numpy to display numbers from 0 to 9999. Uses alpine as the root image.

2. Machine Learning
   
    a. [Openvino](ml/openvino) <br>
        Use openvino deep-learning optimization tools to perform image classification using [SqueezeNet](https://arxiv.org/abs/1602.07360) topology (`squeezenet1.1`). For more information look at [this](ml/openvino/app/public_models/squeezenet1.md) <br>
        FAIL: Could not build

    b. [Pytorch](ml/pytorch) <br>
        Use pytorch open source machine learning library to run [this](ml/pytorch/app/sample.py) sample within SGX-LKL. It uses the `nn` package which modularizes a neural network and implements a two-layer network. 

    c. [Tensorflow](ml/tensorflow) <br>
    FAIL: config file missing 
